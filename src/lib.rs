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
extern crate url;

mod address;
mod common;

pub mod v4;
pub mod v5;

pub use address::Addr;
pub use address::DomainAddr;
pub use address::ToAddr;

use common::*;
use futures::Future;
use futures::done;
use std::net::IpAddr;
use std::net::SocketAddr;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use url::Host;
use url::Url;

/// Creates a new connection using provided proxy URL.
///
/// Proxy URL is specified using following format
/// `protocol://[username:password@]host:port`. Where protocol is one of
/// `socks4`, `socks4a` or `socks5`.
///
/// Note that only SOCKS protocol in version 5 supports username password
/// authentication.
pub fn connect<D>(proxy_url: &str, destination: D, handle: &Handle) -> IoFuture<TcpStream>
    where D: ToAddr 
{
    Box::new(done((|| {
        let url = match Url::parse(proxy_url) {
            Ok(url) => url,
            Err(err) => return Err(invalid_input(format!("proxy: {}: {}", err, proxy_url))),
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
            // TODO use tokio-dns to implement proxy domain name resolution
            Host::Domain(_) => unimplemented!(),
            Host::Ipv4(ip)  => SocketAddr::new(IpAddr::V4(ip), port),
            Host::Ipv6(ip)  => SocketAddr::new(IpAddr::V6(ip), port),
        };
        let username = url.username();
        let password = url.password().unwrap_or("");
        let auth = if !username.is_empty() || !password.is_empty() {
            v5::Auth::UserPass(username.to_owned(), password.to_owned())
        } else {
            v5::Auth::None
        };
        let destination = try!(destination.to_addr());
        Ok((url.scheme().to_owned(), address, destination, auth, handle.clone()))
    })()).and_then(|(scheme, address, destination, auth, handle)| {
        match scheme.as_str() {
            "socks4"  => v4::connect(&address, destination, &handle),
            "socks4a" => v4::connect(&address, destination, &handle),
            "socks5"  => v5::connect(&address, destination, auth, &handle),
            _         => Box::new(done(Err(invalid_input(format!("proxy: Unsupported scheme {}", scheme))))),
        }
    }))
}


