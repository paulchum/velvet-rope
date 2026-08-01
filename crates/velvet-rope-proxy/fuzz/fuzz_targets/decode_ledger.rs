#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = velvet_rope_proxy::decode_binary_ledger_frames(data);
});
