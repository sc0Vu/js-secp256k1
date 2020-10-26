const benchmark = require('benchmark')
const secp256k121Async = require('js-secp256k1/dist/node-bundle.js')
const secp256k1Async = require('../dist/node-bundle.js')
const obindings = require('secp256k1')
const elliptic = require('elliptic')
const ec = new elliptic.ec('secp256k1')

secp256k1Async().then(function (secp256k1Wasm) {
  secp256k121Async().then(function (secp256k121Wasm) {
    const privkeyBuf = Buffer.from([70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70])
    const ecprivkey = ec.keyFromPrivate(privkeyBuf)
    const msg = require('crypto').randomBytes(32)
    const pubkey = secp256k1Wasm.privkeyToPubkey(privkeyBuf)
    const cpubkey = secp256k1Wasm.serializePubkey(pubkey, true)
    new benchmark.Suite('Sign')
      .add('Secp256k1 WASM (current)', () => secp256k1Wasm.sign(msg, privkeyBuf))
      .add('Secp256k1 0.2.1 WASM (current)', () => secp256k121Wasm.sign(msg, privkeyBuf))
      .add('GYP Binding (secp256k1)', () => obindings.sign(msg, privkeyBuf))
      .add('Pure JS (elliptic)', () => ecprivkey.sign(msg))
      .on('cycle', (event) => {
        console.log(String(event.target))
      })
      .on('complete', function () {
        console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
      })
      .run()

    const sig = secp256k1Wasm.sign(msg, privkeyBuf)
    const sig2 = {
      r: sig.signature.slice(0, 32),
      s: sig.signature.slice(32)
    }

    new benchmark.Suite('Recover')
      .add('Secp256k1 WASM (current)', () => secp256k1Wasm.recover(msg, sig.signature, sig.recovery))
      .add('Secp256k1 0.2.1 WASM (current)', () => secp256k121Wasm.recover(msg, sig.signature, sig.recovery))
      .add('GYP Binding (secp256k1)', () => obindings.recover(msg, sig.signature, sig.recovery))
      .add('Pure JS (elliptic)', () => ec.recoverPubKey(msg, sig2, sig.recovery))
      .on('cycle', (event) => {
        console.log(String(event.target))
      })
      .on('complete', function () {
        console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
      })
      .run()

    new benchmark.Suite('Verify')
      .add('Secp256k1 WASM (current)', () => secp256k1Wasm.verify(msg, sig.signature, pubkey))
      .add('GYP Binding (secp256k1)', () => obindings.verify(msg, sig.signature, cpubkey))
      .add('Pure JS (elliptic)', () => ecprivkey.verify(msg, sig2))
      .on('cycle', (event) => {
        console.log(String(event.target))
      })
      .on('complete', function () {
        console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
      })
      .run()
  })
})
