#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = omp_core::v02::detect_version(data);
    let _ = omp_core::v02::parse::<omp_core::v02::Manifest>(data);
    let _ = omp_core::v02::parse::<omp_core::v02::License>(data);
    let _ = omp_core::v02::parse::<omp_core::v02::TrustBundle>(data);
});
