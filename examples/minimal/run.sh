#/bin/bash
set -e

#cp ../../../decent-auth-rs/target/wasm32-wasip1/release/decent_auth_rs.wasm ../../decent_auth.wasm
cp ../../../decent-auth-rs/target/wasm32-wasip1/release/decentauth.wasm ../../decent_auth.wasm
go build
./minimal $@
