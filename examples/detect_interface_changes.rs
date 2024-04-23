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
    let mut if_change_notifier = if_addrs::IfChangeNotifier::new().unwrap();
    println!("Waiting for interface changes...");
    loop {
        if let Ok(details) = if_change_notifier.wait(None) {
            println!("Network interfaces changed: {:#?}", details);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    panic!("Interface change API is not implemented for macOS or iOS");
}
