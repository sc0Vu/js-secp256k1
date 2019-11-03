const benchmark = require('benchmark')
const secp256k1Async = require('../index').node
const obindings = require('secp256k1')
const elliptic = require('elliptic')
const ec = new elliptic.ec('secp256k1')

secp256k1Async().then(function (secp256k1Wasm) {
  const privkeyBuf = Buffer.from([70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70])
  const ecprivkey = ec.keyFromPrivate(privkeyBuf)
  const msg = require('crypto').randomBytes(32)
  new benchmark.Suite('Sign')
    .add('Secp256k1 wasm (current)', () => secp256k1Wasm.sign(msg, privkeyBuf))
    .add('Binding (secp256k1)', () => obindings.sign(msg, privkeyBuf))
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
    .add('Secp256k1 wasm (current)', () => secp256k1Wasm.recover(msg, sig.signature, sig.recovery))
    .add('Binding (secp256k1)', () => obindings.recover(msg, sig.signature, sig.recovery))
    .add('Pure JS (elliptic)', () => ec.recoverPubKey(msg, sig2, sig.recovery))
    .on('cycle', (event) => {
      console.log(String(event.target))
    })
    .on('complete', function () {
      console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
    })
    .run()
})
