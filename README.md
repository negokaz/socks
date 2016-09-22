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

let proxy = "socks5://user:pass@127.0.0.1:1080";
let dest = "example.com:80";

socks::connect(&proxy, dest, reactor.remote()).and_then(|conn| {
  ...
});
```

Complete code can be found in examples directory.

## License

socks is distributed under the terms of MIT license and Apache License Version
2.0. See LICENSE-APACHE and LICENSE-MIT files for details.

