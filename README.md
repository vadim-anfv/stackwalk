# stackwalk

Write a Bitcoin spending condition as a policy, miniscript or descriptor (or raw Script), see the Script it compiles to and step through its execution with the stack drawn at every opcode.

- policy -> miniscript -> descriptor (with its BIP-380 checksum) -> Script, one way, as you type
- every spend path of the descriptor, including ones that fail and why
- step through a run: what each opcode does, the stack (and the alt stack) after it
- the witness or scriptSig as sent, its size in vbytes, op count and Bitcoin Core limits per path
- works on a phone

Live at [vadim.rs/stackwalk](https://vadim.rs/stackwalk) (soon).

## Run locally

You need a recent stable Rust (edition 2024, Rust 1.85 or newer).

```sh
cd server
cargo run
```

Open http://127.0.0.1:5173. A debug build serves `web/` from disk and reloads the page when a file there changes.

To restart the server on Rust changes too, run [bacon](https://github.com/Canop/bacon) in `server/` instead of `cargo run`.

To open it from another device (a phone on the same network), bind more addresses:

```sh
BIND=127.0.0.1:5173,192.168.1.10:5173 cargo run
```

### Release build

```sh
cd server
cargo build --release
```

The page is embedded in the binary at build time (`server/build.rs`), so `stackwalk-server` is the whole app: copy it anywhere and run it. It listens on `BIND` (default `127.0.0.1:5173`); put a reverse proxy in front of it to serve it publicly.

### Tests

```sh
cd server
cargo test
```

## Layout

- `web/` - the page: plain HTML, CSS and JS modules, no build step
- `server/` - the backend (axum): compiles the input with rust-miniscript and runs every spend path, see [API.md](API.md)
- `server/src/scriptexec/` - the Script interpreter, vendored from [rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec) with local changes (listed in its `mod.rs`)

## Keys and signatures

With **test keys** on, keys are names (`A`, `B`, ...) mapped to fixed test keys, and signatures are made over a dummy transaction. Descriptors with real public keys work too, but they are run with test keys of the same names: the Script shape and sizes are right, the key and signature bytes are not yours. Nothing here signs or broadcasts anything.

## Credits

- [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) and [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
- [rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec) (CC0-1.0)
- the title font: Bicubik by Anton Kudin (Jovanny Lemonad freeware)

## License

TBD
