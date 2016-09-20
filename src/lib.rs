// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

//! This crate implements an asynchronous SOCKS proxy client for Tokio.
//!
//! It builds with Cargo. To use it in your project include following in your
//! `Cargo.toml` file:
//! 
//! ```Cargo
//! [dependencies]
//! socks = { git = "https://github.com/tmiasko/socks" }
//! ```
//!
//! # Examples
//!
//! ```rust,no_run
//! extern crate socks;
//! extern crate tokio_core;
//!
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let proxy = "socks5://192.168.0.1:1080";
//!     let destination = "example.com:80";
//!     let mut reactor = Core::new().unwrap();
//!     let conn = socks::connect(proxy, destination, &reactor.handle());
//!     reactor.run(conn).unwrap();
//! }
//! ```

#![feature(try_from)]
#![deny(missing_docs)]

extern crate byteorder;
extern crate futures;
extern crate tokio_core;
extern crate tokio_dns;
extern crate url;

mod address;
mod common;

pub mod v4;
pub mod v5;

pub use address::ToAddr;

use address::Addr;
use address::DomainAddr;
use common::*;
use futures::Future;
use futures::done;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_dns::tcp_connect;
use url::Host;
use url::Url;

/// Creates a new connection using provided proxy URL.
///
/// Format of proxy URL is:
///
/// `protocol://[username:password@]host:port`
/// 
/// Where protocol is one of `socks4`, `socks4a` or `socks5`. Note that only
/// version 5 of SOCKS protocol supports username-password authentication.
///
pub fn connect<D>(proxy_url: &str, destination: D, handle: &Handle) -> IoFuture<TcpStream>
    where D: ToAddr 
{
    Box::new(done((|| {
        let url = match Url::parse(proxy_url) {
            Ok(url) => url,
            Err(err) => return Err(invalid_input(format!("proxy: {}: {}", err, proxy_url))),
        };
        let version = match url.scheme() {
            "socks4"  => Version::V4,
            "socks4a" => Version::V4,
            "socks5"  => Version::V5,
            _ => return Err(invalid_input(format!("proxy: Unsupported scheme {}", url.scheme()))),
        };
        let host = match url.host() {
            Some(host) => host,
            None => return Err(invalid_input(format!("proxy: Missing host {}", proxy_url))),
        };
        let port = match url.port_or_known_default() {
            Some(port) => port,
            None => return Err(invalid_input(format!("proxy: Missing port {}", proxy_url))),
        };
        let address = match host {
            Host::Domain(domain) => Addr::Domain(DomainAddr::new(domain, port)),
            Host::Ipv4(ip)  => Addr::V4(SocketAddrV4::new(ip, port)),
            Host::Ipv6(ip)  => Addr::V6(SocketAddrV6::new(ip, port, 0, 0)),
        };
        let username = url.username();
        let password = url.password().unwrap_or("");
        let auth = if !username.is_empty() || !password.is_empty() {
            v5::Auth::UserPass(username.to_owned(), password.to_owned())
        } else {
            v5::Auth::None
        };
        let destination = try!(destination.to_addr());
        Ok((version, address, destination, auth, handle.clone()))
    })()).and_then(|(version, address, destination, auth, handle)| {
        tcp_connect(&address, &handle).and_then(move |stream| {
            match version {
                Version::V4 => v4::connect_stream(stream, destination),
                Version::V5 => v5::connect_stream(stream, destination, auth),
            }
        })
    }))
}

/// Version of SOCKS protocol.
enum Version { V4, V5 }

