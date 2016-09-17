extern crate futures;
extern crate socks;
extern crate tokio_core;

use futures::Future;
use std::io::Write;
use std::io::stdout;
use std::net::SocketAddr;
use tokio_core::io::read_to_end;
use tokio_core::io::write_all;
use tokio_core::reactor::Core;

fn main() {
    let mut reactor = Core::new().unwrap();
    let handle = reactor.handle();

    let proxy: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let dest = "example.com:80";
    let auth = socks::v5::Auth::None;

    let future = socks::v5::connect(&proxy, dest, auth, &handle).and_then(|stream| {
        write_all(stream, "GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n")
    }).and_then(|(stream, _)| {
        read_to_end(stream, Vec::new())
    }).map(|(_, buff)| {
        stdout().write_all(&buff).unwrap();
    });

    reactor.run(future).unwrap();
}
