//! Drives compact-JWS decoding + ID-JAG claim parsing — the first code that
//! touches attacker-supplied `assertion` bytes at the Resource AS, before any
//! signature check runs.
#![cfg_attr(fuzzing, no_main)]

#[cfg(not(fuzzing))]
use libfuzzer_sys as _;
#[cfg(not(fuzzing))]
use xaa as _;

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    xaa::__fuzz::id_jag_decode(data);
});

#[cfg(not(fuzzing))]
fn main() {}
