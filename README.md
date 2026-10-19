# stackwalk

Step through Bitcoin Script with the stack drawn at every opcode. Write a policy, miniscript or descriptor (or raw Script), pick a spend path, walk the run.

Live at [vadim.rs/stackwalk](https://vadim.rs/stackwalk) (soon).

**Experimental, for learning.** The interpreter is not Bitcoin Core's and is not checked against it yet. Don't rely on it for real funds. It never needs private keys: don't paste them.

## Run

Rust 1.88 or newer.

```sh
cd server
cargo run              # http://127.0.0.1:5173, reloads on changes in web/
cargo build --release  # one binary, the page embedded
cargo test
```

`BIND=127.0.0.1:5173,192.168.1.10:5173` listens on more addresses (a phone on the LAN). The JSON API is in [API.md](API.md).

## Notes

- `web/` is the page (plain JS modules, no build step), `server/` the backend (axum, rust-miniscript).
- Test keys: `A`, `B`, ... are fixed test keys; signatures are over a dummy transaction. Real keys are run as test keys of the same names.
- `server/src/scriptexec/` is vendored from [rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec) (CC0) with local changes, listed in its `mod.rs`.
- PRs welcome; `cargo test` and `cargo clippy --all-targets` should pass.

## License

MIT or Apache-2.0, at your option. Exceptions (the vendored interpreter, the title font Bicubik) are in [LICENSE](LICENSE).
