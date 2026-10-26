#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = omp_core::v02::validate_portable_path(text);
        let _ = omp_crypto::public_key_from_base64url(text);
        let _ = omp_crypto::signing_key_from_base64url(text);
    }
});
