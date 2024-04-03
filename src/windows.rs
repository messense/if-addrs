// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use std::ffi::CStr;
use std::time::Duration;
use std::{io, ptr};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HANDLE, NO_ERROR, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelIPChangeNotify, GetAdaptersAddresses, NotifyAddrChange, GAA_FLAG_INCLUDE_PREFIX,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_PREFIX_XP, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::Networking::WinSock::{WSACloseEvent, WSACreateEvent, WSAGetLastError, WSA_IO_PENDING};
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapFree, HEAP_NONE, HEAP_ZERO_MEMORY,
};
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::OVERLAPPED;

#[repr(transparent)]
pub struct IpAdapterAddresses(*const IP_ADAPTER_ADDRESSES_LH);

impl IpAdapterAddresses {
    #[allow(unsafe_code)]
    pub fn name(&self) -> String {
        let len = (0..)
            .take_while(|&i| unsafe { *(*self.0).FriendlyName.offset(i) } != 0)
            .count();
        let slice = unsafe { std::slice::from_raw_parts((*self.0).FriendlyName, len) };
        String::from_utf16_lossy(slice)
    }

    #[allow(unsafe_code)]
    pub fn adapter_name(&self) -> String {
        unsafe { CStr::from_ptr((*self.0).AdapterName as _) }
            .to_string_lossy()
            .into_owned()
    }

    pub fn ipv4_index(&self) -> Option<u32> {
        let if_index = unsafe { (*self.0).Anonymous1.Anonymous.IfIndex };
        if if_index == 0 {
            None
        } else {
            Some(if_index)
        }
    }

    pub fn ipv6_index(&self) -> Option<u32> {
        let if_index = unsafe { (*self.0).Ipv6IfIndex };
        if if_index == 0 {
            None
        } else {
            Some(if_index)
        }
    }

    pub fn prefixes(&self) -> PrefixesIterator {
        PrefixesIterator {
            _head: unsafe { &*self.0 },
            next: unsafe { (*self.0).FirstPrefix },
        }
    }

    pub fn unicast_addresses(&self) -> UnicastAddressesIterator {
        UnicastAddressesIterator {
            _head: unsafe { &*self.0 },
            next: unsafe { (*self.0).FirstUnicastAddress },
        }
    }
}

pub struct IfAddrs {
    inner: IpAdapterAddresses,
}

impl IfAddrs {
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        let mut buffersize = 15000;
        let mut ifaddrs: *mut IP_ADAPTER_ADDRESSES_LH;

        loop {
            unsafe {
                ifaddrs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize as _)
                    as *mut IP_ADAPTER_ADDRESSES_LH;
                if ifaddrs.is_null() {
                    panic!("Failed to allocate buffer in get_if_addrs()");
                }

                let retcode = GetAdaptersAddresses(
                    0,
                    GAA_FLAG_SKIP_ANYCAST
                        | GAA_FLAG_SKIP_MULTICAST
                        | GAA_FLAG_SKIP_DNS_SERVER
                        | GAA_FLAG_INCLUDE_PREFIX,
                    ptr::null_mut(),
                    ifaddrs,
                    &mut buffersize,
                );

                match retcode {
                    ERROR_SUCCESS => break,
                    ERROR_BUFFER_OVERFLOW => {
                        HeapFree(GetProcessHeap(), HEAP_NONE, ifaddrs as _);
                        buffersize *= 2;
                        continue;
                    }
                    _ => {
                        HeapFree(GetProcessHeap(), HEAP_NONE, ifaddrs as _);
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }

        Ok(Self {
            inner: IpAdapterAddresses(ifaddrs),
        })
    }

    pub fn iter(&self) -> IfAddrsIterator {
        IfAddrsIterator {
            _head: self,
            next: self.inner.0,
        }
    }
}

impl Drop for IfAddrs {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            HeapFree(GetProcessHeap(), HEAP_NONE, self.inner.0 as _);
        }
    }
}

pub struct IfAddrsIterator<'a> {
    _head: &'a IfAddrs,
    next: *const IP_ADAPTER_ADDRESSES_LH,
}

impl<'a> Iterator for IfAddrsIterator<'a> {
    type Item = IpAdapterAddresses;

    #[allow(unsafe_code)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next.is_null() {
            return None;
        };

        Some(unsafe {
            let result = &*self.next;
            self.next = (*self.next).Next;

            IpAdapterAddresses(result)
        })
    }
}

pub struct PrefixesIterator<'a> {
    _head: &'a IP_ADAPTER_ADDRESSES_LH,
    next: *const IP_ADAPTER_PREFIX_XP,
}

impl<'a> Iterator for PrefixesIterator<'a> {
    type Item = &'a IP_ADAPTER_PREFIX_XP;

    #[allow(unsafe_code)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next.is_null() {
            return None;
        };

        Some(unsafe {
            let result = &*self.next;
            self.next = (*self.next).Next;

            result
        })
    }
}

pub struct UnicastAddressesIterator<'a> {
    _head: &'a IP_ADAPTER_ADDRESSES_LH,
    next: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
}

impl<'a> Iterator for UnicastAddressesIterator<'a> {
    type Item = &'a IP_ADAPTER_UNICAST_ADDRESS_LH;

    #[allow(unsafe_code)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.next.is_null() {
            return None;
        };

        Some(unsafe {
            let result = &*self.next;
            self.next = (*self.next).Next;

            result
        })
    }
}

/// Block until the OS reports that the network interface list has changed, or
/// until an optional timeout. Returns an [`io::ErrorKind::WouldBlock`] error on
/// timeout, or another error if the network notifier could not be set up.
pub fn detect_interface_changes(timeout: Option<Duration>) -> io::Result<()> {
    let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
    let mut notify_event: HANDLE = Default::default();
    overlap.hEvent = unsafe { WSACreateEvent() };

    let ret = unsafe { NotifyAddrChange(&mut notify_event, &overlap) };

    if ret != NO_ERROR {
        let code = unsafe { WSAGetLastError() };
        if code != WSA_IO_PENDING {
            unsafe { WSACloseEvent(overlap.hEvent) };
            return Err(io::Error::from_raw_os_error(code));
        }
    }

    let millis = if let Some(timeout) = timeout {
        timeout.as_millis().try_into().expect("timeout overflow")
    } else {
        INFINITE
    };

    let ret = match unsafe { WaitForSingleObject(overlap.hEvent, millis) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT | WAIT_ABANDONED => Err(io::Error::new(io::ErrorKind::WouldBlock, "Timed out")),
        _ => Err(io::Error::last_os_error()),
    };
    unsafe {
        CancelIPChangeNotify(&overlap);
        WSACloseEvent(overlap.hEvent);
    };

    ret
}
