#![no_main]

use git_vault::event::EventLog;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(log) = EventLog::decode(bytes) {
        let _ = log.encode();
    }
});
