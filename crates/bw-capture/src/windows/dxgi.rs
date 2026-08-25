use crate::backend::{CaptureBackend, CaptureError};
use crate::cursor::{CursorInfo, CursorShape};
use crate::frame::{DirtyRect, Frame, PixelFormat};
use crate::monitor::DisplayInfo;

use std::ptr;
use windows::core::Interface;
use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE};
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::UI::WindowsAndMessaging::{GetCursorInfo, CURSORINFO, CURSOR_SHOWING};

/// DXGI desktop-duplication capture backend (Windows only).
///
/// Uses `IDXGIOutputDuplication` to acquire frames with dirty-rectangle
/// tracking. All COM/DirectX calls are `unsafe` by API design; this is
/// confined to the Windows backends and reviewed on a per-call basis.
pub struct DxgiCaptureBackend {
    device: Option<ID3D11Device>,
    context: Option<ID3D11DeviceContext>,
    duplication: Option<IDXGIOutputDuplication>,
    staging_texture: Option<ID3D11Texture2D>,
    active_display: Option<DisplayInfo>,
    width: u32,
    height: u32,
    /// Last known cursor state extracted from frame acquisition.
    last_cursor: CursorInfo,
}

impl DxgiCaptureBackend {
    /// Creates a new, uninitialized DXGI capture backend.
    pub fn new() -> Result<Self, CaptureError> {
        Ok(Self {
            device: None,
            context: None,
            duplication: None,
            staging_texture: None,
            active_display: None,
            width: 0,
            height: 0,
            last_cursor: CursorInfo::default(),
        })
    }

    fn init_d3d11() -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
        let feature_levels = [
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0,
            D3D_FEATURE_LEVEL_9_3,
        ];

        let mut device = None;
        let mut context = None;
        let mut feature_level = D3D_FEATURE_LEVEL_11_0;

        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&feature_levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut feature_level),
                Some(&mut context),
            )
            .map_err(|e| CaptureError::InitFailed(format!("D3D11CreateDevice failed: {}", e)))?;
        }

        let device = device.ok_or_else(|| CaptureError::InitFailed("Device is null".into()))?;
        let context = context.ok_or_else(|| CaptureError::InitFailed("Context is null".into()))?;

        Ok((device, context))
    }

    fn create_staging_texture(
        device: &ID3D11Device,
        width: u32,
        height: u32,
    ) -> Result<ID3D11Texture2D, CaptureError> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };

        let mut texture = None;
        unsafe {
            device
                .CreateTexture2D(&desc, None, Some(&mut texture))
                .map_err(|e| CaptureError::InitFailed(format!("CreateTexture2D failed: {}", e)))?;
        }

        texture.ok_or_else(|| CaptureError::InitFailed("Staging texture is null".into()))
    }
}

impl CaptureBackend for DxgiCaptureBackend {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        let mut displays = Vec::new();

        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1()
                .map_err(|e| CaptureError::DisplayEnumerationFailed(e.to_string()))?;

            let mut adapter_idx = 0;
            while let Ok(adapter) = factory.EnumAdapters1(adapter_idx) {
                let mut output_idx = 0;
                while let Ok(output) = adapter.EnumOutputs(output_idx) {
                    if let Ok(desc) = output.GetDesc() {
                        let name_len = desc
                            .DeviceName
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(desc.DeviceName.len());
                        let name_utf16 = &desc.DeviceName[..name_len];
                        let name = String::from_utf16_lossy(name_utf16);

                        let width =
                            (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
                        let height =
                            (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;

                        let id = format!("{}_{}", adapter_idx, output_idx);

                        displays.push(DisplayInfo {
                            id,
                            name,
                            width,
                            height,
                            virtual_x: desc.DesktopCoordinates.left,
                            virtual_y: desc.DesktopCoordinates.top,
                            refresh_hz: 60, // TODO: query properly
                            scale_factor: 1.0,
                            is_primary: desc.DesktopCoordinates.left == 0
                                && desc.DesktopCoordinates.top == 0,
                        });
                    }
                    output_idx += 1;
                }
                adapter_idx += 1;
            }
        }

        Ok(displays)
    }

    fn start(&mut self, display: &DisplayInfo) -> Result<(), CaptureError> {
        let (device, context) = Self::init_d3d11()?;
        self.device = Some(device.clone());
        self.context = Some(context);

        // Find the specific output
        unsafe {
            let dxgi_device: IDXGIDevice = device
                .cast()
                .map_err(|e| CaptureError::InitFailed(format!("Device cast failed: {}", e)))?;
            let adapter: IDXGIAdapter = dxgi_device
                .GetAdapter()
                .map_err(|e| CaptureError::InitFailed(format!("GetAdapter failed: {}", e)))?;

            // Re-parse the ID to find the right output
            let parts: Vec<&str> = display.id.split('_').collect();
            if parts.len() != 2 {
                return Err(CaptureError::InvalidDisplay);
            }
            let output_idx = parts[1]
                .parse::<u32>()
                .map_err(|_| CaptureError::InvalidDisplay)?;

            let output = adapter
                .EnumOutputs(output_idx)
                .map_err(|e| CaptureError::InitFailed(format!("EnumOutputs failed: {}", e)))?;

            let output1: IDXGIOutput1 = output
                .cast()
                .map_err(|e| CaptureError::InitFailed(format!("Output1 cast failed: {}", e)))?;

            let duplication = output1.DuplicateOutput(&dxgi_device).map_err(|e| {
                if e.code() == E_ACCESSDENIED {
                    CaptureError::AccessDenied
                } else {
                    CaptureError::InitFailed(format!("DuplicateOutput failed: {}", e))
                }
            })?;

            self.duplication = Some(duplication);
        }

        self.width = display.width;
        self.height = display.height;
        self.active_display = Some(display.clone());
        self.staging_texture = Some(Self::create_staging_texture(
            &device,
            display.width,
            display.height,
        )?);

        Ok(())
    }

    fn next_frame(&mut self) -> Result<Frame, CaptureError> {
        let duplication = self.duplication.as_ref().ok_or(CaptureError::Stopped)?;
        let context = self.context.as_ref().ok_or(CaptureError::Stopped)?;
        let staging_texture = self.staging_texture.as_ref().ok_or(CaptureError::Stopped)?;

        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        unsafe {
            // Check for timeout
            match duplication.AcquireNextFrame(100, &mut frame_info, &mut resource) {
                Ok(_) => {}
                Err(e) => {
                    let code = e.code().0 as u32;
                    if code == 0x887A0027u32 {
                        // DXGI_ERROR_WAIT_TIMEOUT — screen is idle but cursor may
                        // have moved. Query Win32 directly so the remote crosshair
                        // tracks the cursor even when the desktop is static.
                        let mut ci = CURSORINFO {
                            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
                            ..Default::default()
                        };
                        let cursor = if GetCursorInfo(&mut ci).is_ok() {
                            let pt = ci.ptScreenPos;
                            let visible = (ci.flags.0 & CURSOR_SHOWING.0) != 0;
                            CursorInfo {
                                x: pt.x,
                                y: pt.y,
                                visible,
                                shape: CursorShape::Arrow,
                                bitmap: None,
                                bitmap_width: 0,
                                bitmap_height: 0,
                            }
                        } else {
                            self.last_cursor.clone()
                        };

                        self.last_cursor = cursor.clone();
                        return Ok(Frame {
                            width: self.width,
                            height: self.height,
                            stride: self.width * 4,
                            timestamp_us: 0,
                            pixel_format: PixelFormat::Bgra8,
                            buffer: vec![],
                            dirty_rects: vec![],
                            move_rects: vec![],
                            cursor: Some(cursor),
                            is_refresh: false,
                        });
                    }
                    if code == 0x887A0026u32 || code == 0x887A0001u32 || code == 0x80070005u32 {
                        // DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_INVALID_CALL, E_ACCESSDENIED
                        self.stop(); // Trigger recovery on next start
                    }
                    return Err(CaptureError::FrameAcquisitionFailed(format!(
                        "AcquireNextFrame: {}",
                        e
                    )));
                }
            }

            let resource = resource.ok_or_else(|| {
                CaptureError::FrameAcquisitionFailed("AcquireNextFrame returned no resource".into())
            })?;
            let texture: ID3D11Texture2D = resource.cast().map_err(|e| {
                CaptureError::FrameAcquisitionFailed(format!("Texture cast: {}", e))
            })?;

            // Copy to staging texture
            context.CopyResource(staging_texture, &texture);

            // Map staging texture
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            context
                .Map(staging_texture, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| CaptureError::FrameAcquisitionFailed(format!("Map: {}", e)))?;

            let stride = mapped.RowPitch;
            let size_bytes = (stride * self.height) as usize;

            let mut buffer = vec![0u8; size_bytes];
            ptr::copy_nonoverlapping(mapped.pData as *const u8, buffer.as_mut_ptr(), size_bytes);

            context.Unmap(staging_texture, 0);

            // Extract dirty and move rects
            let mut dirty_rects = Vec::new();
            let mut move_rects = Vec::new();

            if frame_info.TotalMetadataBufferSize > 0 {
                let mut buffer_size = frame_info.TotalMetadataBufferSize;
                let mut raw_rects = vec![0u8; buffer_size as usize];

                // First get move rects
                if duplication
                    .GetFrameMoveRects(
                        buffer_size,
                        raw_rects.as_mut_ptr() as *mut _,
                        &mut buffer_size,
                    )
                    .is_ok()
                {
                    let rect_count =
                        buffer_size as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
                    let rects: &[DXGI_OUTDUPL_MOVE_RECT] =
                        std::slice::from_raw_parts(raw_rects.as_ptr() as *const _, rect_count);
                    for r in rects {
                        move_rects.push(crate::frame::MoveRect {
                            source_point_x: r.SourcePoint.x as u32,
                            source_point_y: r.SourcePoint.y as u32,
                            dest_rect: DirtyRect {
                                x: r.DestinationRect.left as u32,
                                y: r.DestinationRect.top as u32,
                                width: (r.DestinationRect.right - r.DestinationRect.left) as u32,
                                height: (r.DestinationRect.bottom - r.DestinationRect.top) as u32,
                            },
                        });
                    }
                }

                // Then get dirty rects
                buffer_size = frame_info.TotalMetadataBufferSize;
                if duplication
                    .GetFrameDirtyRects(
                        buffer_size,
                        raw_rects.as_mut_ptr() as *mut _,
                        &mut buffer_size,
                    )
                    .is_ok()
                {
                    let rect_count = buffer_size as usize
                        / std::mem::size_of::<windows::Win32::Foundation::RECT>();
                    let rects: &[windows::Win32::Foundation::RECT] =
                        std::slice::from_raw_parts(raw_rects.as_ptr() as *const _, rect_count);
                    for r in rects {
                        dirty_rects.push(DirtyRect {
                            x: r.left as u32,
                            y: r.top as u32,
                            width: (r.right - r.left) as u32,
                            height: (r.bottom - r.top) as u32,
                        });
                    }
                }
            }
            if dirty_rects.is_empty() && move_rects.is_empty() {
                dirty_rects.push(DirtyRect {
                    x: 0,
                    y: 0,
                    width: self.width,
                    height: self.height,
                });
            }

            duplication.ReleaseFrame().map_err(|e| {
                CaptureError::FrameAcquisitionFailed(format!("ReleaseFrame: {}", e))
            })?;

            // Extract cursor position from the frame info. The pointer
            // position is updated whenever the mouse moves, regardless of
            // whether the desktop composition changed.
            let cursor = {
                let pos = frame_info.PointerPosition.Position;
                let visible = frame_info.PointerPosition.Visible.as_bool();
                CursorInfo {
                    x: pos.x,
                    y: pos.y,
                    visible,
                    shape: CursorShape::Arrow, // TODO: map PointerType
                    bitmap: None,              // TODO: GetFramePointerShape
                    bitmap_width: 0,
                    bitmap_height: 0,
                }
            };
            self.last_cursor = cursor.clone();

            Ok(Frame {
                width: self.width,
                height: self.height,
                stride,
                timestamp_us: frame_info.LastPresentTime as u64,
                pixel_format: PixelFormat::Bgra8,
                buffer,
                dirty_rects,
                move_rects,
                cursor: Some(cursor),
                is_refresh: false,
            })
        }
    }

    fn cursor_info(&mut self) -> Result<CursorInfo, CaptureError> {
        if self.duplication.is_none() {
            return Err(CaptureError::Stopped);
        }
        // Return the last cursor position extracted during frame acquisition.
        Ok(self.last_cursor.clone())
    }

    fn stop(&mut self) {
        self.duplication = None;
        self.staging_texture = None;
        self.context = None;
        self.device = None;
        self.active_display = None;
        self.last_cursor = CursorInfo::default();
    }
}
