# sui-light-client

A barebones, read-only client implementation for sui.
It should work with previous versions of sui crates/types, unlike the `SuiClient`.
It also should be faster than `SuiClient`


# run tests

`RUST_LOG=trace cargo test`


# install

Add this line to your `cargo.toml`

```
sui-light-client = { git="https://github.com/daweth/sui-light-client" }
```
