// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

//! This crate implements an asynchronous SOCKS proxy client for Tokio.

#![feature(try_from)]
#![deny(missing_docs)]

extern crate byteorder;
extern crate futures;
extern crate tokio_core;

mod address;
mod protocol;

pub use address::Addr;
pub use address::DomainAddr;
pub use address::ToAddr;
pub use protocol::connect;
pub use protocol::connect_stream;
