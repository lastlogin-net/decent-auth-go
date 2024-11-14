module github.com/lastlogin-net/decent-auth-go

go 1.23.1

replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go

require (
	github.com/anderspitman/little-oauth2-go v0.0.0-20240920175702-3cf95e45e957
	github.com/philippgille/gokv v0.7.0
	github.com/philippgille/gokv/file v0.7.0
	github.com/philippgille/gokv/gomap v0.7.0
)

require (
	github.com/philippgille/gokv/encoding v0.7.0 // indirect
	github.com/philippgille/gokv/util v0.7.0 // indirect
)
