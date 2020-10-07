# js-secp256k1
[![Build Status](https://travis-ci.org/sc0Vu/js-secp256k1.svg?branch=master)](https://travis-ci.org/sc0Vu/js-secp256k1)
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
$ sh build.sh
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

Secp256k1 WASM (current) x 3,911 ops/sec ±0.84% (96 runs sampled)
GYP Binding (secp256k1) x 1,162 ops/sec ±0.67% (92 runs sampled)
Pure JS (elliptic) x 1,255 ops/sec ±0.16% (96 runs sampled)
Sign: fastest is Secp256k1 WASM (current)
Secp256k1 WASM (current) x 1,671 ops/sec ±1.32% (96 runs sampled)
GYP Binding (secp256k1): 
Pure JS (elliptic) x 393 ops/sec ±2.32% (77 runs sampled)
Recover: fastest is Secp256k1 WASM (current)
Secp256k1 WASM (current) x 1,647 ops/sec ±1.68% (87 runs sampled)
GYP Binding (secp256k1): 
Pure JS (elliptic) x 499 ops/sec ±2.94% (84 runs sampled)
Verify: fastest is Secp256k1 WASM (current)
```

# License

MIT

