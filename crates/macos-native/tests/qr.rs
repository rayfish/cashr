//! Vision integration tests use disposable QR fixtures generated with Core Image.
#![cfg(target_os = "macos")]

use macos_native::qr;

#[test]
fn decodes_a_pairing_uri_without_changing_its_payload() {
    let codes = qr::decode(include_bytes!("fixtures/qr-pairing.png")).unwrap();
    assert_eq!(
        codes,
        vec![format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example.com&secret=qr-test",
            "a".repeat(64)
        )]
    );
}

#[test]
fn returns_all_codes_for_the_user_to_choose() {
    let mut codes = qr::decode(include_bytes!("fixtures/qr-multiple.png")).unwrap();
    codes.sort();
    assert_eq!(codes, vec!["byrgi-test-one", "byrgi-test-two"]);
}

#[test]
fn blank_and_invalid_images_give_recoverable_errors() {
    assert!(qr::decode(include_bytes!("fixtures/qr-blank.png"))
        .unwrap_err()
        .contains("No readable QR"));
    assert!(qr::decode(b"not an image").is_err());
    assert!(qr::decode(&[]).is_err());
}
