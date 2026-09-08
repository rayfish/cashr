//! QR generation stays local; encoded contents never enter logs or URLs.
use qrcode::{Color, EcLevel, QrCode};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
pub struct QrView {
    width: usize,
    modules: Vec<bool>,
}

#[tauri::command]
pub fn encode_qr(value: String) -> Result<QrView, String> {
    let value = Zeroizing::new(value);
    if value.is_empty() || value.len() > 6000 {
        return Err("This content is too large for a single QR code. Use Copy instead.".into());
    }
    let code = QrCode::with_error_correction_level(value.as_bytes(), EcLevel::M)
        .map_err(|_| "This content is too large for a single QR code. Use Copy instead.")?;
    Ok(QrView {
        width: code.width(),
        modules: code
            .into_colors()
            .into_iter()
            .map(|color| color == Color::Dark)
            .collect(),
    })
}
