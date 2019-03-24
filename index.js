const KECCAK = require('./lib/keccak-tiny.js')
const isBuffer = require('is-buffer')

module.exports = function () {
  return new Promise(function (resolve, reject) {
    KECCAK().then(function (k) {
      let keccakTiny = {}
      keccakTiny.hashAlgos = {
        shake128: {
          length: 16,
          functionName: '_shake128'
        },
        shake256: {
          length: 32,
          functionName: '_shake256'
        },
        sha3_224: {
          length: 28,
          functionName: '_sha3_224'
        },
        sha3_256: {
          length: 32,
          functionName: '_sha3_256'
        },
        sha3_384: {
          length: 48,
          functionName: '_sha3_384'
        },
        sha3_512: {
          length: 64,
          functionName: '_sha3_512'
        },
        keccak224: {
          length: 28,
          functionName: '_keccak_224'
        },
        keccak256: {
          length: 32,
          functionName: '_keccak_256'
        },
        keccak384: {
          length: 48,
          functionName: '_keccak_384'
        },
        keccak512: {
          length: 64,
          functionName: '_keccak_512'
        }
      }
      keccakTiny.k = k
      keccakTiny.hash = function (hashAlgoName, msg) {
        if (typeof hashAlgoName !== 'string') {
          throw new Error('Hash algorithm name must be string.')
        }
        if (typeof this.hashAlgos[hashAlgoName] === undefined) {
          throw new Error('Unknown hash algorithm.')
        }
        if (isBuffer(msg) !== true) {
          throw new Error('Message must be buffer.')
        }
        let hashAlgo = this.hashAlgos[hashAlgoName]
        let hashLen = hashAlgo.length
        let hashMem = this.k._malloc(hashLen)
        let msgLen = msg.length
        let msgMem = this.k._malloc(msgLen)
        let hash = new Uint8Array(hashLen)
        let hashFunc = this.k[hashAlgo.functionName]
        this.k.HEAP8.set(msg, msgMem)
        let res = hashFunc(hashMem, hashLen, msgMem, msgLen)
        if (res === -1) {
          throw new Error('Hash failed.')
          return
        }
        for (var i=0; i<hashLen; i++) {
          var v = this.k.getValue(hashMem + i, 'i8')
          hash[i] = v
        }
        // free memory
        this.k._free(hashMem)
        return Buffer.from(hash)
      }
      Object.keys(keccakTiny.hashAlgos).forEach(function (hashAlgoName) {
        keccakTiny[hashAlgoName] = function (msg) {
          let msgBuf = Buffer.from(msg)
          return keccakTiny.hash(hashAlgoName, msgBuf)
        }
      })
      resolve(keccakTiny)
    })
  })
}
