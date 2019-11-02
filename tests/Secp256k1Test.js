const assert = require('assert')
const Secp256k1Async = require('../index').node
const Secp256k1 = require('secp256k1')

describe('Secp256k1Test', function () {
  var secp256k1
  // EIP155
  var privkey = Buffer.from([70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70,70])
  var msg = Buffer.from([218,245,167,121,174,151,47,151,33,151,48,61,123,87,71,70,199,239,131,234,218,192,242,121,26,210,61,185,46,76,142,83])

  beforeEach(async function () {
    secp256k1 = await Secp256k1Async()
  })

  it ('Shoud sign message', function (done) {
    let newSig = secp256k1.sign(msg, privkey)
    let newSig2 = Secp256k1.sign(msg, privkey)
    assert(newSig !== false)
    assert(newSig.signature.equals(newSig2.signature))
    assert.equal(newSig.recovery, newSig2.recovery)
    done()
  })

  it ('Should verify signature', function (done) {
    let newSig = secp256k1.sign(msg, privkey)
    let pubkey = secp256k1.privkeyToPubkey(privkey)
    assert(secp256k1.verify(msg, newSig.signature, pubkey))
    done()
  })
})