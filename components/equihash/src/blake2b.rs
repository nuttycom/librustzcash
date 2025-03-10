// Copyright (c) 2020-2022 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// This module uses unsafe code for FFI into blake2b.
#![allow(unsafe_code)]

use blake2b_simd::{State, PERSONALBYTES};

use std::boxed::Box;
use std::ptr;
use std::slice;

#[no_mangle]
pub(crate) extern "C" fn blake2b_init(
    output_len: usize,
    personalization: *const [u8; PERSONALBYTES],
) -> *mut State {
    let personalization = unsafe { personalization.as_ref().unwrap() };

    Box::into_raw(Box::new(
        blake2b_simd::Params::new()
            .hash_length(output_len)
            .personal(personalization)
            .to_state(),
    ))
}

#[no_mangle]
pub(crate) extern "C" fn blake2b_clone(state: *const State) -> *mut State {
    unsafe { state.as_ref() }
        .map(|state| Box::into_raw(Box::new(state.clone())))
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub(crate) extern "C" fn blake2b_free(state: *mut State) {
    if !state.is_null() {
        drop(unsafe { Box::from_raw(state) });
    }
}

#[no_mangle]
pub(crate) extern "C" fn blake2b_update(state: *mut State, input: *const u8, input_len: usize) {
    let state = unsafe { state.as_mut().unwrap() };
    let input = unsafe { slice::from_raw_parts(input, input_len) };

    state.update(input);
}

#[no_mangle]
pub(crate) extern "C" fn blake2b_finalize(state: *mut State, output: *mut u8, output_len: usize) {
    let state = unsafe { state.as_mut().unwrap() };
    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };

    // Allow consuming only part of the output.
    let hash = state.finalize();
    assert!(output_len <= hash.as_bytes().len());
    output.copy_from_slice(&hash.as_bytes()[..output_len]);
}
