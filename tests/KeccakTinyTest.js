const assert = require('assert')
const keccakAsync = require('../index')
const keccakHash = require('keccak')

describe('KeccakTinyTest', function () {
  var keccakTiny
  var msg = Buffer.from('helloworld', 'utf8')

  beforeEach(async function () {
    keccakTiny = await keccakAsync()
  })

  it ('Shoud hash message', function (done) {
    Object.keys(keccakTiny.hashAlgos).forEach(function (hashName) {
      var hashName2 = hashName.split('_').join('-')
      var hash1 = keccakTiny[hashName].call(keccakTiny, msg).toString('hex')
      var hash2 = keccakHash(hashName2).update(msg)
      if (hash2.digest === undefined) {
        hash2 = hash2.squeeze(keccakTiny.hashAlgos[hashName].length, 'hex')
      } else {
        hash2 = hash2.digest('hex')
      }
      assert.equal(hash2, hash1)
    })
    done()
  })
})