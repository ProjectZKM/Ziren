module github.com/ProjectZKM/zkm-recursion-gnark

go 1.23.0

toolchain go1.23.11

require (
	github.com/consensys/gnark v0.10.1-0.20240504023521-d9bfacd7cb60
	github.com/consensys/gnark-crypto v0.14.1-0.20240909142611-e6b99e74cec1
)

require (
	github.com/bits-and-blooms/bitset v1.14.2 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-ignition-verifier v0.0.0-20230527014722-10693546ab33
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/ingonyama-zk/icicle v1.1.0 // indirect
	github.com/ingonyama-zk/iciclegnark v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ronanh/intcomp v1.1.0 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/consensys/gnark => github.com/alpenlabs/gnark v0.0.0-20250707125522-2d480d810efb

replace github.com/consensys/gnark-crypto => github.com/alpenlabs/gnark-crypto v0.0.0-20250521035818-134953372b00
