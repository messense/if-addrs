// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

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
