// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use std::env;

fn main() {
    let mut cfg = cc::Build::new();
    if env::var("TARGET").unwrap().contains("android") {
        cfg.include("native")
            .file("native/ifaddrs.c")
            .compile("libifaddrs.a");
    }
}
