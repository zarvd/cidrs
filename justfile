default:
    just --list

# Build the project
build:
    cargo build

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo fmt -- --check
    cargo clippy --all-targets --all-features

# Run unit tests against the current platform
unit-test:
    cargo nextest run --all-features
    cargo test --doc --all-features

# Run benchmarks
bench:
    cargo bench --all-features
