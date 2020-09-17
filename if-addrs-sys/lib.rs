// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
#![cfg(target_os = "android")]
extern crate libc;

use libc::{c_char, c_int, c_uint, c_void, sockaddr};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: ::c_uint,
    pub ifa_addr: *mut ::sockaddr,
    pub ifa_netmask: *mut ::sockaddr,
    pub ifa_ifu: *mut ::sockaddr,
    pub ifa_data: *mut ::c_void,
}

extern "C" {
    pub fn getifaddrs(ifap: *mut *mut ::ifaddrs) -> ::c_int;
    pub fn freeifaddrs(ifa: *mut ::ifaddrs);
}
