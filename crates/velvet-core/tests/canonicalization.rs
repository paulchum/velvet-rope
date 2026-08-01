use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;
use serde_json::Value;
use velvet_core::{
    VELVET_CANONICAL_JSON_V1, canonical_json_v1_hash, canonical_json_v1_string,
    load_canonical_json_v1, proof_artifact_canonical_json, proof_artifact_hash,
};

fn fixture_dir() -> PathBuf {
    let relative = PathBuf::from("tests/fixtures/canonicalization/v1");
    let manifest_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(&relative);
    if manifest_candidate.join("manifest.json").is_file() {
        return manifest_candidate;
    }

    let cwd_candidate = std::env::current_dir()
        .expect("current working directory")
        .join(&relative);
    if cwd_candidate.join("manifest.json").is_file() {
        return cwd_candidate;
    }

    manifest_candidate
}

#[test]
fn shared_canonicalization_vectors_are_stable() {
    let fixture_dir = fixture_dir();
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(fixture_dir.join("manifest.json")).expect("manifest should load"),
    )
    .expect("manifest should parse");
    assert_eq!(
        manifest["canonicalization"].as_str(),
        Some(VELVET_CANONICAL_JSON_V1)
    );

    let vectors = manifest["vectors"].as_array().expect("vectors array");
    for vector in vectors {
        let artifact_type = vector["type"].as_str().expect("vector type");
        let file = vector["file"].as_str().expect("vector file");
        let expected_canonical = vector["expected_canonical"]
            .as_str()
            .expect("expected canonical");
        let expected_hash = vector["sha256"].as_str().expect("expected sha256");

        let payload =
            load_canonical_json_v1(&fs::read(fixture_dir.join(file)).expect("fixture should load"))
                .expect("fixture should parse");
        assert_eq!(
            proof_artifact_canonical_json(artifact_type, &payload).expect("canonical JSON"),
            expected_canonical
        );
        assert_eq!(
            proof_artifact_hash(artifact_type, &payload).expect("hash"),
            expected_hash
        );
        assert_eq!(
            proof_artifact_hash(artifact_type, &payload).expect("stable hash"),
            expected_hash
        );
    }
}

#[test]
fn canonicalization_rejects_unsupported_json_values() {
    let invalid_inputs: &[&[u8]] = &[
        br#"{"a":1,"a":2}"#,
        br#"{"entry_price":1.5}"#,
        br#"{"value":NaN}"#,
        br#"{"value":Infinity}"#,
        br#"{"soft_ceiling_fraction":"01.20"}"#,
        br#"{"limit_usd":1}"#,
        br#"{"entry_price":"-0.0000"}"#,
        br#"{"decided_at":"2026-05-27T19:04:00+00:00"}"#,
        br#"{"bad_unicode":"\ud800"}"#,
        b"\xef\xbb\xbf{}",
    ];

    for raw in invalid_inputs {
        assert!(
            load_canonical_json_v1(raw).is_err(),
            "input should fail: {}",
            String::from_utf8_lossy(raw)
        );
    }
}

fn object_json<'a>(entries: impl Iterator<Item = (&'a String, &'a i64)>) -> String {
    let fields = entries
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(key).expect("test key serializes"),
                value
            )
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", fields.join(","))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn canonicalization_is_stable_across_object_key_order(
        entries in proptest::collection::btree_map("[a-z][a-z0-9_]{0,12}", -1_000_000i64..1_000_000, 0..32)
    ) {
        let forward = object_json(entries.iter());
        let reverse = object_json(entries.iter().rev());
        let forward_value = load_canonical_json_v1(forward.as_bytes())
            .expect("generated forward JSON should be canonicalizable");
        let reverse_value = load_canonical_json_v1(reverse.as_bytes())
            .expect("generated reverse JSON should be canonicalizable");

        prop_assert_eq!(
            canonical_json_v1_string(&forward_value).expect("forward canonicalizes"),
            canonical_json_v1_string(&reverse_value).expect("reverse canonicalizes")
        );
        prop_assert_eq!(
            canonical_json_v1_hash(&forward_value).expect("forward hashes"),
            canonical_json_v1_hash(&reverse_value).expect("reverse hashes")
        );
    }
}
