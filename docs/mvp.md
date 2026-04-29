# Rust++ MVP

This repository implements the first Rust++ slice as an opt-in Rust workspace:

- `rustpp-attributes`: attribute macros for `#[component]`, `#[contract]`, `#[requires]`, `#[ensures]`, `#[effects]`, and `#[unsafe_boundary]`
- `stdpp`: small standard-library extension crate, `refined_type!`, `capability!`, and prelude
- `rpp`: command-line wrapper for `check`, `test`, `build`, `audit`, `effects`, `policy`, `sbom`, `prove`, `lower`, `expand`, and `new`
- `examples/payment_service`: a minimal component/contract/effect example
- `examples/rpp/minimal.rpp`: a minimal `.rpp` lowering example
- `examples/unsafe_boundary.rs`: a sample unsafe boundary metadata annotation
- `rustpp.toml`: a minimal policy file for unsafe, effect, and contract inventory checks

The MVP intentionally lowers to normal Rust. The contract macros currently generate debug assertions for preconditions and simple postconditions.

## Commands

```bash
cargo run -p rpp --bin rpp -- ci --report rustpp-report.json
cargo run -p rpp --bin rpp -- check -- --workspace
cargo test --workspace
cargo run -p payment_service
cargo run -p rpp --bin rpp -- audit .
cargo run -p rpp --bin rpp -- audit --json .
cargo run -p rpp --bin rpp -- effects .
cargo run -p rpp --bin rpp -- effects --json .
cargo run -p rpp --bin rpp -- effects --deny Db .
cargo run -p rpp --bin rpp -- effects --json --deny Db .
cargo run -p rpp --bin rpp -- policy .
cargo run -p rpp --bin rpp -- sbom
cargo run -p rpp --bin rpp -- report .
cargo run -p rpp --bin rpp -- migrate examples/payment_service
cargo run -p rpp --bin rpp -- migrate --json examples/payment_service
cargo run -p rpp --bin rpp -- lower examples/rpp/minimal.rpp
cargo run -p rpp --bin rpp -- prove .
cargo run -p rpp --bin rpp -- prove --json .
cargo run -p rpp --bin cargo-pp -- pp check -- --workspace
cargo run -p rpp --bin cargo-pp -- pp ci --report rustpp-report.json
```

`rpp ci` is the single local and GitHub Actions entrypoint. It runs policy enforcement, `cargo check --workspace`, `cargo test --workspace`, and `rpp report`. With `--report`, it writes the combined JSON report to a file:

```bash
cargo run -p rpp --bin rpp -- ci --report rustpp-report.json
```

`rpp check` enforces `rustpp.toml` first, then forwards remaining arguments to `cargo check`. Use `--no-policy` when you intentionally want the raw Cargo behavior:

```bash
cargo run -p rpp --bin rpp -- check --no-policy -- --workspace
```

`cargo-pp` is the MVP stand-in for `cargo++`. It delegates Rust++ commands to the sibling `rpp` binary, so both forms are valid once the tools are built:

```bash
cargo run -p rpp --bin rpp -- check -- --workspace
cargo run -p rpp --bin cargo-pp -- pp check -- --workspace
```

## Current Contract Semantics

`#[requires(expr)]` injects this at the start of the function body:

```rust
debug_assert!((expr), "Rust++ requires failed: expr");
```

`#[ensures(expr)]` wraps the function body and binds the returned value as `result` by reference:

```rust
let __rustpp_result = { original_body };
let result = &__rustpp_result;
debug_assert!((expr), "Rust++ ensures failed: expr");
__rustpp_result
```

This is deliberately small and transparent. A real verifier can replace this lowering once `rpp prove` grows solver integration.

## Refinement Types

`stdpp` exposes a small `refined_type!` macro for value-constrained newtypes:

```rust
refined_type! {
    pub struct PositiveMoney(i64) where |value| *value > 0, "amount must be positive";
}
```

The generated type has `new`, `TryFrom`, `get`, `into_inner`, `AsRef`, and `Deref` implementations. In the payment example, `PositiveMoney` replaces a raw `i64`, so invalid amounts are rejected before `PaymentService::charge` can be called.

## Capabilities

`stdpp` also exposes a `capability!` macro for named effect/capability markers:

```rust
capability!(Db);
capability!(Time);
```

Each capability implements `stdpp::effect::Capability` and converts into an `Effect`, giving `#[effects(Db, Time)]` a concrete marker type to grow into.

## Effect Audit

`rpp effects` scans Rust and Rust++ source files for effect annotations:

```rust
#[effects(Db, Time)]
async fn charge(...) -> Result<PaymentId> {
    ...
}
```

The scanner reports each annotation and can enforce a simple deny list:

```bash
cargo run -p rpp --bin rpp -- effects --deny Net .
```

If a denied effect is present, the command exits with status code `2`, which is intended for CI policy checks.

Use `--json` to emit the same inventory plus denied-effect matches as `rustpp-effects-v0`.

## Policy File

`rpp policy` reads `rustpp.toml` and enforces the first trust policy surface:

```toml
[policy]
deny_unsafe = true
deny_effects = ["Net"]
min_contract_annotations = 1
```

The MVP parser intentionally supports only these keys. That keeps the policy format small while still making generated code and CI checks explicit. `min_contract_annotations` fails the policy check when the scanned source tree has fewer contract annotations than the configured minimum.

## SBOM

`rpp sbom` reads `Cargo.lock` and emits a minimal package inventory:

```bash
cargo run -p rpp --bin rpp -- sbom
cargo run -p rpp --bin rpp -- sbom --json
```

The MVP SBOM includes package name, version, and source. Workspace packages use `workspace` as their text source and `null` in JSON.

## Combined Report

`rpp report` emits a single JSON document for CI and audit logs. It combines:

- unsafe keyword findings and unsafe boundary metadata
- effect annotations
- policy violations
- contract annotation inventory
- the minimal SBOM

```bash
cargo run -p rpp --bin rpp -- report .
cargo run -p rpp --bin cargo-pp -- pp report .
```

The command exits with status code `2` if unsafe findings, unsafe boundary metadata errors, or policy violations are present.

## Contract Inventory

`rpp prove` is inventory-only in the MVP. It scans `.rs` attributes and `.rpp` metadata for contract annotations, then prints the source location, contract kind, and expression. `--json` emits the same data in `rustpp-prove-v0` format for CI logs or review tooling.

```bash
cargo run -p rpp --bin rpp -- prove .
cargo run -p rpp --bin rpp -- prove --json .
```

Static solver integration is intentionally left for a later Rust++ phase.

## Migration Scan

`rpp migrate` is scan-only. It does not rewrite files; it reports places where ordinary Rust might benefit from Rust++ concepts:

- `struct` declarations that may become `#[component]`
- `trait` declarations that may become `protocol`
- `async fn` signatures without effect annotations
- primitive type aliases that may become refinement types
- raw primitive domain parameters such as `amount`, `count`, `size`, `len`, or `id`
- visible unsafe keyword usage without unsafe boundary metadata

```bash
cargo run -p rpp --bin rpp -- migrate examples/payment_service
cargo run -p rpp --bin rpp -- migrate --json examples/payment_service
```

## Unsafe Boundary Audit

`rpp audit` reports direct `unsafe` keyword usage and recognizes explicit unsafe boundary metadata:

```rust
#[unsafe_boundary(reason = "C ABI boundary placeholder", audit = "2026-04")]
fn ffi_boundary_placeholder() {}
```

Boundary annotations must include both `reason` and `audit`; missing metadata is treated as an audit failure. Valid boundary metadata is reported without failing the command unless direct unsafe usage is also found.

Use `--json` to emit a standalone `rustpp-audit-v0` document with unsafe findings, unsafe boundaries, metadata errors, and pass/fail status.

## `.rpp` Lowering Preview

`rpp lower` is a deliberately small Phase B preview. It currently lowers the two headline design units:

```rust
contract type PositiveMoney = i64 where |value| *value > 0;

protocol Repository {
    fn len(&self) -> usize;
}

component Service<R: Repository> {
    repo: R,
}
```

to normal Rust:

```rust
refined_type! {
    struct PositiveMoney(i64) where |value| *value > 0;
}

trait Repository {
    fn len(&self) -> usize;
}

struct Service<R: Repository> {
    repo: R,
}
```

This gives the project a real place to grow `.rpp` syntax without requiring a custom backend.
