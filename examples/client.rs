extern crate async_socks as socks;
extern crate futures;
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
    println!("Proxy address: {}", proxy);

    let destination = "example.com:80";
    println!("Destination address: {}", destination);

    let future = socks::connect(&proxy, destination, &handle).and_then(|(addr, stream)| {
        println!("Proxy bound address: {}", addr);
        write_all(stream, "GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n")
    }).and_then(|(stream, _)| {
        read_to_end(stream, Vec::new())
    }).map(|(_, buff)| {
        stdout().write_all(&buff).unwrap();
    });

    reactor.run(future).unwrap();
}
