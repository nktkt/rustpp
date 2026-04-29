# Rust++

Rust++ is an experimental, verification-oriented, component-based, effect-aware layer on top of Rust for building trustworthy large-scale systems.

The project starts as an opt-in Rust workspace rather than a Rust fork. The current MVP lowers to ordinary Rust and focuses on contracts, effects, refinement types, unsafe boundary auditing, policy checks, and a minimal trusted-build toolchain.

## Status

This repository is a working MVP, not a production language implementation. It intentionally keeps the first slice small:

- Rust-compatible attribute macros
- A small `stdpp` support crate
- `rpp` command-line tooling
- `.rpp` syntax lowering preview
- CI-friendly policy, effect, unsafe, and SBOM checks

The original Japanese proposal is preserved in [`docs/proposal-ja.md`](docs/proposal-ja.md).

## Workspace

```text
.
├── crates
│   ├── rustpp-attributes   # #[component], #[requires], #[ensures], #[effects], ...
│   ├── stdpp               # prelude, refined_type!, capability!, support types
│   └── rpp                 # Rust++ CLI and cargo-pp wrapper
├── examples
│   ├── payment_service     # component/contract/effect/refinement sample
│   ├── rpp/minimal.rpp     # .rpp lowering sample
│   └── unsafe_boundary.rs  # unsafe boundary metadata sample
├── docs
│   ├── mvp.md
│   └── proposal-ja.md
└── rustpp.toml             # policy configuration
```

## Features

### Contracts

```rust
#[requires(value > 0)]
fn double(value: i32) -> i32 {
    value * 2
}

#[ensures(*result > 0)]
fn positive(value: i32) -> i32 {
    value
}
```

`#[requires]` and `#[ensures]` currently lower to `debug_assert!` checks.

### Refinement Types

```rust
use stdpp::prelude::*;

refined_type! {
    pub struct PositiveMoney(i64) where |value| *value > 0, "amount must be positive";
}
```

The generated type provides `new`, `TryFrom`, `get`, `into_inner`, `AsRef`, and `Deref`.

### Capabilities and Effects

```rust
capability!(Db);
capability!(Time);

#[effects(Db, Time)]
async fn charge(amount: PositiveMoney) -> Result<PaymentId> {
    // ...
}
```

`rpp effects` scans Rust and `.rpp` files for effect annotations and can enforce deny lists.

### `.rpp` Lowering Preview

```rust
contract type PositiveMoney = i64 where |value| *value > 0;

protocol Repository {
    fn len(&self) -> usize;
}

component Service<R: Repository> {
    repo: R,
}
```

`rpp lower` currently lowers this preview syntax to ordinary Rust constructs and `stdpp` macros.

## Quick Start

```bash
cargo run -p rpp --bin rpp -- check -- --workspace
cargo test --workspace
cargo run -p payment_service
```

Expected sample output:

```text
payment_id=1
```

## Tooling

```bash
# Enforce rustpp.toml policy, then run cargo check
cargo run -p rpp --bin rpp -- check -- --workspace

# Raw cargo check through rpp
cargo run -p rpp --bin rpp -- check --no-policy -- --workspace

# Unsafe keyword and unsafe boundary metadata audit
cargo run -p rpp --bin rpp -- audit .

# Effect inventory and deny-list check
cargo run -p rpp --bin rpp -- effects .
cargo run -p rpp --bin rpp -- effects --deny Net .

# Policy enforcement
cargo run -p rpp --bin rpp -- policy .

# Minimal SBOM from Cargo.lock
cargo run -p rpp --bin rpp -- sbom
cargo run -p rpp --bin rpp -- sbom --json

# Combined JSON report
cargo run -p rpp --bin rpp -- report .

# Contract inventory
cargo run -p rpp --bin rpp -- prove .

# .rpp lowering preview
cargo run -p rpp --bin rpp -- lower examples/rpp/minimal.rpp

# cargo++ MVP stand-in
cargo run -p rpp --bin cargo-pp -- pp check -- --workspace
```

## Policy

`rustpp.toml` defines the first trusted-build policy surface:

```toml
[policy]
deny_unsafe = true
deny_effects = ["Net"]
```

## Roadmap

- Expand `.rpp` parsing beyond line-oriented lowering
- Add structured contract/effect metadata
- Add richer unsafe boundary reports
- Expand machine-readable audit reports
- Grow `rpp prove` from inventory into verifier integration
- Improve `cargo-pp` into a full `cargo++` workflow

## License

This project is intended to be licensed under `MIT OR Apache-2.0`.
