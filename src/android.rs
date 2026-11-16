//! `getifaddrs` and `freeifaddrs` for Android.
//!
//! These functions were only added to bionic in API level 24. To support older versions, they are
//! looked up at runtime and if they are not available, a netlink-based fallback is used instead.

use crate::netlink;
use libc::{c_int, ifaddrs};
use std::{mem, sync::OnceLock};

type GetIfAddrsFn = unsafe extern "C" fn(*mut *mut ifaddrs) -> c_int;
type FreeIfAddrsFn = unsafe extern "C" fn(*mut ifaddrs);

/// Same as `libc::getifaddrs`.
#[allow(unsafe_code)]
pub unsafe fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int {
    if let Some((getifaddrs, _)) = libc_fns() {
        return getifaddrs(ifap);
    }

    match netlink::getifaddrs() {
        Ok(ifa) => {
            *ifap = ifa;
            0
        }
        Err(error) => {
            *libc::__errno() = error.raw_os_error().unwrap_or(libc::EIO);
            -1
        }
    }
}

/// Same as `libc::freeifaddrs`.
#[allow(unsafe_code)]
pub unsafe fn freeifaddrs(ifa: *mut ifaddrs) {
    if let Some((_, freeifaddrs)) = libc_fns() {
        freeifaddrs(ifa)
    } else {
        netlink::freeifaddrs(ifa)
    }
}

// `c"..."` literals would need Rust 1.77 but the MSRV is 1.71.
#[allow(unsafe_code, clippy::manual_c_str_literals)]
pub(crate) fn libc_fns() -> Option<(GetIfAddrsFn, FreeIfAddrsFn)> {
    static FNS: OnceLock<Option<(GetIfAddrsFn, FreeIfAddrsFn)>> = OnceLock::new();

    *FNS.get_or_init(|| unsafe {
        let get = libc::dlsym(libc::RTLD_DEFAULT, b"getifaddrs\0".as_ptr().cast());
        let free = libc::dlsym(libc::RTLD_DEFAULT, b"freeifaddrs\0".as_ptr().cast());

        if get.is_null() || free.is_null() {
            None
        } else {
            Some((
                mem::transmute::<*mut libc::c_void, GetIfAddrsFn>(get),
                mem::transmute::<*mut libc::c_void, FreeIfAddrsFn>(free),
            ))
        }
    })
}
