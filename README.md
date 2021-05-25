# js-secp256k1
[![CI](https://github.com/sc0Vu/js-secp256k1/actions/workflows/ci.yml/badge.svg)](https://github.com/sc0Vu/js-secp256k1/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sc0Vu/js-secp256k1/branch/master/graph/badge.svg)](https://codecov.io/gh/sc0Vu/js-secp256k1)

Compiled webassembly of bitcoin secp256k1

# Install

* install library

```BASH
$ npm install js-secp256k1
```

# Build with emscripten

You can build secp256k1 wasm yourself with emscripten. We build two version of secp256k1 - node and web. The only difference is that there is no file system in web version.

```BASH
$ ./build.sh
```

After build wasm files, you should build javascript library again.

```BASH
$ npm run build
```

# Usage

* Hash message
```JS
// for nodejs
const secp256k1Async = require('js-secp256k1/dist/node-bundle')

// for browser
const secp256k1Async = require('js-secp256k1/dist/bundle')

// initialize the library
secp256k1 = await secp256k1Async()

// generate public key from private key
const privKey = Buffer.from([......])
// browser
const privKey = new Uint8Array([......])

let pubkey = secp256k1.privkeyToPubkey(privkey)

// serialize public key
let compressed = true
let cpubkey = secp256k1.serializePubkey(pubkey, compressed)

// sign
// signature {
//   signature: <Buffer/Uint8Array>,
//   recovery: <int>
// }
let sig = secp256k1.sign(msg, privkey)

// verify
let isVerified secp256k1.verify(msg, sig.signature, pubkey)

// recover
let rpubkey = secp256k1.recover(msg, sig.signature, sig.recovery)
```

# Benchmark

Computer: 2.2 GHz 6-Core Intel Core i7

```
$ node -v
v12.18.1

> secp256k1-benchmark@0.0.0 start /Users/peterlai/Desktop/Projects/js-secp256k1/benchmarks
> node index.js

Secp256k1 WASM (current) x 3,979 ops/sec ±0.22% (94 runs sampled)
Secp256k1 0.2.1 WASM (current) x 3,865 ops/sec ±1.08% (96 runs sampled)
GYP Binding (secp256k1) x 1,156 ops/sec ±1.17% (93 runs sampled)
Pure JS (elliptic) x 1,249 ops/sec ±0.57% (96 runs sampled)
Sign: fastest is Secp256k1 WASM (current)
Secp256k1 WASM (current) x 2,275 ops/sec ±0.55% (98 runs sampled)
Secp256k1 0.2.1 WASM (current) x 1,734 ops/sec ±0.07% (97 runs sampled)
GYP Binding (secp256k1): 
Pure JS (elliptic) x 460 ops/sec ±0.32% (93 runs sampled)
Recover: fastest is Secp256k1 WASM (current)
Secp256k1 WASM (current) x 2,757 ops/sec ±0.08% (96 runs sampled)
GYP Binding (secp256k1): 
Pure JS (elliptic) x 548 ops/sec ±0.34% (95 runs sampled)
Verify: fastest is Secp256k1 WASM (current)
```

# License

MIT

