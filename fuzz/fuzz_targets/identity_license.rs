#![no_main]
use libfuzzer_sys::fuzz_target;
use omp_identity::{ProductionFactProvider, ValidatedFactProvider};
fuzz_target!(|data: &[u8]| {
    let _ = omp_core::v02::parse::<omp_core::v02::IdentityDocument>(data);
    let _ = omp_core::v02::parse::<omp_core::v02::KeyLifecycleEvent>(data);
    let _ = omp_core::v02::parse::<omp_core::v02::License>(data);
    let _ = omp_core::v02::parse::<omp_core::v02::TimeAnchor>(data);
    let _ = ProductionFactProvider.identity_document(data);
});
