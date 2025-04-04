module github.com/lastlogin-net/decent-auth-go

go 1.24.1

replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go
//replace github.com/lastlogin-net/decent-auth-build => ../decent-auth-build

require (
	github.com/extism/go-sdk v1.6.2-0.20241121002538-bef00f39873e
	github.com/lastlogin-net/decent-auth-build v0.0.0-20250404183723-46b2c2f50617
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/philippgille/gokv/file v0.7.0
	github.com/tetratelabs/wazero v1.8.1
)

require (
	github.com/dylibso/observe-sdk/go v0.0.0-20240819160327-2d926c5d788a // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20240805132620-81f5be970eca // indirect
	github.com/philippgille/gokv/encoding v0.7.0 // indirect
	github.com/philippgille/gokv/util v0.7.0 // indirect
	github.com/tetratelabs/wabin v0.0.0-20230304001439-f6f874872834 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
