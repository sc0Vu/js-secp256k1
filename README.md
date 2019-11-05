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

# License

MIT

