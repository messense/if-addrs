// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Interface change notifier example.

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    println!("Waiting for interface changes...");
    loop {
        if if_addrs::detect_interface_changes(None).is_ok() {
            println!("Network interfaces changed");
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    println!("Interface change API is not implemented for macOS or iOS");
}
