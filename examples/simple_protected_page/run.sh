#/bin/bash
set -e

cp ../../../decent-auth-rs/target/wasm32-wasip1/release/decentauth.wasm ../../decentauth.wasm
go build
./simple_protected_page $@
