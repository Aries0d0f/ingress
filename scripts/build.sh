#!/bin/sh
# Builds the wasm Worker with worker-build.
set -eu

if command -v rustup >/dev/null 2>&1; then
	PATH="$(dirname "$(rustup which rustc)"):$PATH"
fi
PATH="$HOME/.cargo/bin:$PATH"

cargo install -q --locked worker-build --version '^0.8'
worker-build --release
