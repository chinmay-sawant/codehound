#[path = "helpers/mod.rs"]
mod helpers;

use insta::assert_snapshot;
use slopguard::reporting::json::Envelope;

#[test]
fn envelope_snapshot_is_stable() {
    let sample = helpers::reporting::sample();
    let env = Envelope::from(&sample);
    let mut s = serde_json::to_string_pretty(&env).unwrap();
    // Redact version-specific fields so the snapshot survives releases.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&s) {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("version");
        }
        s = serde_json::to_string_pretty(&v).unwrap();
    }
    assert_snapshot!("json_envelope", s);
}
