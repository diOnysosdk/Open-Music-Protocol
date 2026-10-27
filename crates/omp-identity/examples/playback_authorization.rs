//! Make a playback-availability decision without granting new authority.

use omp_identity::{
    evaluate_playback, Authorization, CurrentStatus, PlaybackDecision, PlaybackInput,
};

fn main() {
    let decision = evaluate_playback(&PlaybackInput {
        authorization: Authorization::AuthorizedCurrent,
        current_status: CurrentStatus::Active,
        public_unrestricted: true,
        restricted_operation: false,
        pin: None,
        exact_pin_match: false,
        pin_state_integrity: false,
        adr007_conflicted_pinned: false,
        adr008_stale_permanent: false,
    });
    assert_eq!(decision, PlaybackDecision::PlaybackAllowed);
    println!("playback decision: {decision:?}");
}
