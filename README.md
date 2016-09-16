# socks

Asynchronous SOCKS proxy client for [Tokio](https://github.com/tokio-rs/tokio).

## Usage

Add this to your `Cargo.toml` file:

```
[dependencies]
socks = { git = "https://github.com/tmiasko/socks" }
```

And use as follows:

```rust
extern crate socks;

...

let proxy_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
let conn = socks::connect_v5(&proxy_addr, "example.com:80", &reactor.handle()).map(|(addr, conn)| {
  ...
  Ok(conn)
});
```

Complete code can be found in examples directory.

## License

socks is distributed under the terms of MIT license and Apache License Version
2.0. See LICENSE-APACHE and LICENSE-MIT files for details.

