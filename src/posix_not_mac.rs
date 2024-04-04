use std::mem;
use std::net::UdpSocket;
use std::time::Duration;
use std::{io, os::fd::FromRawFd};

use libc::{bind, close, sockaddr_nl, socket, AF_NETLINK, NETLINK_ROUTE, SOCK_RAW};

pub fn detect_interface_changes(timeout: Option<Duration>) -> io::Result<()> {
    let socket = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut sockaddr: sockaddr_nl = unsafe { mem::zeroed() };
    sockaddr.nl_family = AF_NETLINK as u16;
    sockaddr.nl_groups = 1; // RTNLGRP_LINK

    if unsafe {
        bind(
            socket,
            &sockaddr as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        unsafe { close(socket) };
        return Err(io::Error::last_os_error());
    }

    // lie about the type, since they all use fds and we don't need specifics
    // after we have called bind
    let socket = unsafe { UdpSocket::from_raw_fd(socket) };

    let mut buf = [0u8; 65536];
    socket.set_read_timeout(timeout)?;
    socket.recv(&mut buf)?;

    Ok(())
}
