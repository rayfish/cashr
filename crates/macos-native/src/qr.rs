//! Local QR decoding. Images and decoded payloads never go to a service or log.

#[cfg(target_os = "macos")]
mod platform {
    use std::process::{Command, Stdio};

    use objc2::{rc::autoreleasepool, AnyThread};
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypePNG, NSPasteboardTypeTIFF};
    use objc2_core_graphics::{CGPreflightScreenCaptureAccess, CGRequestScreenCaptureAccess};
    use objc2_foundation::{NSArray, NSData, NSDictionary};
    use objc2_vision::{
        VNBarcodeSymbologyQR, VNDetectBarcodesRequest, VNImageRequestHandler, VNRequest,
    };

    const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;

    /// Called on the app's main thread so permission is attributed to Byrgi.
    pub fn request_screen_access() -> bool {
        CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess()
    }

    pub fn check_screen_access() -> Result<(), String> {
        if CGPreflightScreenCaptureAccess() {
            Ok(())
        } else {
            Err("Allow Byrgi in System Settings → Privacy & Security → Screen Recording, then reopen Byrgi. You can also scan an image from the clipboard.".into())
        }
    }

    /// Read an image only after the user chooses Paste image or presses Cmd+V.
    pub fn clipboard_image() -> Result<Vec<u8>, String> {
        autoreleasepool(|_| {
            let board = NSPasteboard::generalPasteboard();
            // SAFETY: These are immutable AppKit type constants available on macOS 12.
            let image = unsafe {
                board
                    .dataForType(NSPasteboardTypePNG)
                    .or_else(|| board.dataForType(NSPasteboardTypeTIFF))
            }
            .ok_or("Copy an image containing a QR code, then choose Paste image.")?;
            check_size(image.length())?;
            Ok(image.to_vec())
        })
    }

    /// Apple's interactive selector supports multiple displays and Escape to cancel.
    pub fn capture_screen() -> Result<Option<Vec<String>>, String> {
        let directory = tempfile::tempdir().map_err(|_| "Could not prepare screen capture.")?;
        let path = directory.path().join("selection.png");
        let status = Command::new("/usr/sbin/screencapture")
            .args(["-i", "-s", "-x", "-t", "png"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "Could not start the macOS screen selector.")?;
        // Escape leaves no file. The private temporary directory is removed on
        // every exit path, including decoding failures.
        if !path.exists() && (status.success() || status.code() == Some(1)) {
            return Ok(None);
        }
        if !status.success() {
            return Err("Screen capture failed. Check Byrgi's Screen Recording permission or try Paste image.".into());
        }
        let size = std::fs::metadata(&path)
            .map_err(|_| "Could not read the selected image.")?
            .len();
        if size > MAX_IMAGE_BYTES as u64 {
            return Err("Select a smaller area around the QR code.".into());
        }
        let bytes = std::fs::read(&path).map_err(|_| "Could not read the selected image.")?;
        decode(&bytes).map(Some)
    }

    fn check_size(size: usize) -> Result<(), String> {
        if size == 0 || size > MAX_IMAGE_BYTES {
            Err("Choose an image smaller than 32 MB containing a QR code.".into())
        } else {
            Ok(())
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Vec<String>, String> {
        check_size(bytes.len())?;
        autoreleasepool(|_| {
            let data = NSData::with_bytes(bytes);
            let handler = VNImageRequestHandler::initWithData_options(
                VNImageRequestHandler::alloc(),
                &data,
                &NSDictionary::new(),
            );
            // SAFETY: The request is confined to this thread and lives until the
            // synchronous performRequests call finishes. Only QR observations
            // from that request are read; no callbacks or borrowed image memory.
            unsafe {
                let request = VNDetectBarcodesRequest::new();
                let qr = VNBarcodeSymbologyQR.ok_or("QR scanning is unavailable on this Mac.")?;
                request.setSymbologies(&NSArray::from_slice(&[qr]));
                let requests = NSArray::from_slice(&[&*request as &VNRequest]);
                handler
                    .performRequests_error(&requests)
                    .map_err(|_| "Could not decode this image. Try a clearer screenshot.")?;
                let mut codes = Vec::new();
                if let Some(results) = request.results() {
                    for observation in results.iter() {
                        if let Some(value) = observation.payloadStringValue() {
                            let value = value.to_string();
                            if !value.is_empty() && value.len() <= 16_384 && !codes.contains(&value)
                            {
                                codes.push(value);
                            }
                            if codes.len() == 32 {
                                break;
                            }
                        }
                    }
                }
                if codes.is_empty() {
                    Err("No readable QR code found. Include the entire code and its border.".into())
                } else {
                    Ok(codes)
                }
            }
        })
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn request_screen_access() -> bool {
        false
    }
    pub fn check_screen_access() -> Result<(), String> {
        Err("QR scanning requires macOS.".into())
    }
    pub fn clipboard_image() -> Result<Vec<u8>, String> {
        Err("QR scanning requires macOS.".into())
    }
    pub fn capture_screen() -> Result<Option<Vec<String>>, String> {
        Err("QR scanning requires macOS.".into())
    }
    pub fn decode(_: &[u8]) -> Result<Vec<String>, String> {
        Err("QR scanning requires macOS.".into())
    }
}

pub use platform::{
    capture_screen, check_screen_access, clipboard_image, decode, request_screen_access,
};
