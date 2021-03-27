const Secp256k1Wasm = require('./lib/secp256k1.wasm')
const Secp256k1 = require('./lib/secp256k1.js')
const Buffer = require('buffer/').Buffer
const isBuffer = require('is-buffer')

module.exports = function () {
  options = {
    instantiateWasm: function (info, successCallback) {
      return Secp256k1Wasm(info)
              .then(function (i) {
                return successCallback(i.instance)
              })
    }
  }
  return new Promise(function (resolve, reject) {
    Secp256k1(options).then(function (s) {
      let secp256k1 = {}

      // 769 is sign and recover context
      Object.defineProperties(secp256k1, {
        s: {
          writable: false,
          value: s
        },
        ctx: {
          writable: false,
          value: s._secp256k1_context_create(769)
        },
        msgLen: {
          writable: false,
          value: 32
        },
        privkeyLen: {
          writable: false,
          value: 32
        },
        rawSigLen: {
          writable: false,
          value: 64
        },
        sigLen: {
          writable: false,
          value: 65
        },
        pubkeyLen: {
          writable: false,
          value: 64
        },
        SECP256K1_EC_COMPRESSED: {
          writable: false,
          value: 258
        },
        SECP256K1_EC_UNCOMPRESSED: {
          writable: false,
          value: 2
        }
      })

      secp256k1.copyToBuffer = function (src, len) {
        let out = new Buffer(len)
        for (var i=0; i<len; i++) {
          let v = this.s.getValue(src + i, 'i8')
          out[i] = v
        }
        return out
      }

      secp256k1.malloc = function (buf, len) {
        if (buf.length > len) {
          throw new Error('buffer should not exceeds the size')
        }
        let ptr = this.s._malloc(len)
        if (buf.length > 0) {
          this.s.HEAP8.set(buf, ptr)
        }
        return ptr
      }

      secp256k1.free = function (ptr) {
        this.s._free(ptr)
      }

      secp256k1.cleanUp = function () {
        for (let i=0; i<arguments.length; i++) {
          this.free(arguments[i])
        }
      }

      secp256k1.sign = function (msg, privkey) {
        return this._sign(Buffer.from(msg), Buffer.from(privkey))
      }

      secp256k1._sign = function (msgBuf, privkeyBuf) {
        if (isBuffer(privkeyBuf) !== true || privkeyBuf.length !== this.privkeyLen) {
          return false
        }
        if (isBuffer(msgBuf) !== true || msgBuf.length !== this.msgLen) {
          return false
        }
        // verify private key
        let privkey = this.malloc(privkeyBuf, this.privkeyLen)
        let msg = this.malloc(msgBuf, this.msgLen)
        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privkey) !== 1) {
          this.cleanUp(privkey, msg)
          return false
        }
        let empty = Buffer.from([])
        let rawSig = this.malloc(empty, this.sigLen)
        let sig = this.malloc(empty, this.sigLen)
        let rec = this.malloc(empty, 1)
        if (this.s._secp256k1_ecdsa_sign_recoverable(this.ctx, rawSig, msg, privkey, null, null) !== 1) {
          this.leanUp(privkey, msg, rawSig, sig, rec)
          return false
        }
        if (this.s._secp256k1_ecdsa_recoverable_signature_serialize_compact(this.ctx, sig, rec, rawSig) !== 1) {
          this.cleanUp(privkey, msg, rawSig, sig, rec)
          return false
        }
        // set rec to last
        let recid = this.s.getValue(rec, 'i8')
        let pe = this.copyToBuffer(sig, this.rawSigLen)
        this.cleanUp(privkey, msg, rawSig, sig, rec)
        return {
          signature: pe,
          recovery: recid
        }
      }

      secp256k1.combinePubkeys = function(pubkeyArr) {
        return this._combinePubkeys(pubkeyArr.map(Buffer.from))
      }

      secp256k1._combinePubkeys = function(pubkeyBufArr) {
        const concatBuffer = Buffer.alloc(pubkeyBufArr.length * 65, 0)
        pubkeyBufArr.forEach((pubkeyBuf, idx) => {
          pubkeyBuf.copy(concatBuffer, idx * 65)
        })

        const concatBufferPtr = this.malloc(concatBuffer, concatBuffer.length)

        const pubkeyPtrs = []
        for (let idx = 0; idx < pubkeyBufArr.length; idx++) {
          pubkeyPtrs.push(concatBufferPtr + idx * 65);
        }
        const pubkeyPtrArrPtr = this.malloc(Buffer.from([]), pubkeyBufArr.length * 4)
        this.s.HEAP32.set(pubkeyPtrs, pubkeyPtrArrPtr >> 2)

        const empty = Buffer.from([])
        const pubkey = this.malloc(empty, this.pubkeyLen)

        if(this.s._secp256k1_ec_pubkey_combine(this.ctx, pubkey, pubkeyPtrArrPtr, pubkeyBufArr.length) !== 1) {
          this.cleanUp(concatBufferPtr, pubkeyPtrArrPtr, pubkey)
          return false
        }

        const pb = this.copyToBuffer(pubkey, this.pubkeyLen)
        this.cleanUp(concatBufferPtr, pubkeyPtrArrPtr, pubkey)
        return pb
      }

      secp256k1.serializePubkey = function (pubkey, compressed) {
        return this._serializePubkey(Buffer.from(pubkey), compressed)
      }

      secp256k1._serializePubkey = function (pubkeyBuf, compressed) {
        let pubkey = this.malloc(pubkeyBuf, pubkeyBuf.length)
        let pubLen = (compressed) ? 33 : 65;
        let mode = (compressed) ? this.SECP256K1_EC_COMPRESSED : this.SECP256K1_EC_UNCOMPRESSED
        let empty = Buffer.from([])
        let spubkey = this.malloc(empty, pubLen)
        let spubkeyLen = this.malloc(Buffer.from([pubLen]), 1)
        if (this.s._secp256k1_ec_pubkey_serialize(this.ctx, spubkey, spubkeyLen, pubkey, mode) !== 1) {
          this.cleanUp(pubkey, spubkey, spubkeyLen)
          return false
        }
        let pc = this.copyToBuffer(spubkey, pubLen)
        this.cleanUp(pubkey, spubkey, spubkeyLen)
        return pc
      }

      secp256k1.privkeyAddTweak = function (privkey, tweak) {
        return this._privkeyAddTweak(Buffer.from(privkey), Buffer.from(tweak))
      }

      secp256k1._privkeyAddTweak = function (privkeyBuf, tweakBuf) {
        const privkey = this.malloc(privkeyBuf, this.privkeyLen)
        const tweakPtr = this.malloc(tweakBuf, this.privkeyLen)

        if (this.s._secp256k1_ec_seckey_tweak_add(this.ctx, privkey, tweakPtr) !== 1) {
          this.cleanUp(privkey, tweakPtr)
          return false
        }

        const tweakedPrivkey = this.copyToBuffer(privkey, this.privkeyLen)
        this.cleanUp(privkey, tweakPtr)
        return tweakedPrivkey
      }

      secp256k1.privkeyToPubkey = function (privkey) {
        return this._privkeyToPubkey(Buffer.from(privkey))
      }

      secp256k1._privkeyToPubkey = function (privkeyBuf) {
        if (isBuffer(privkeyBuf) !== true || privkeyBuf.length !== this.msgLen) {
          return false
        }
        // verify private key
        let empty = Buffer.from([])
        let privkey = this.malloc(privkeyBuf, this.privkeyLen)
        let pubkey = this.malloc(empty, this.pubkeyLen)
        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privkey) !== 1) {
          this.cleanUp(privkey, pubkey)
          return false
        }
        if (this.s._secp256k1_ec_pubkey_create(this.ctx, pubkey, privkey) !== 1) {
          this.cleanUp(privkey, pubkey)
          return false
        }
        let pb = this.copyToBuffer(pubkey, this.pubkeyLen)
        return pb
      }

      secp256k1.verify = function (msg, sig, pubkey) {
        return this._verify(Buffer.from(msg), Buffer.from(sig), Buffer.from(pubkey))
      }

      secp256k1._verify = function (msgBuf, sigBuf, pubkeyBuf) {
        if (isBuffer(msgBuf) !== true || msgBuf.length !== this.msgLen) {
          return false
        }
        if (isBuffer(sigBuf) !== true || sigBuf.length !== (this.sigLen - 1)) {
          return false
        }
        if (isBuffer(pubkeyBuf) !== true || pubkeyBuf.length !== 64) {
          return false
        }
        let empty = Buffer.from([])
        let sigData = this.malloc(sigBuf, this.rawSigLen)
        let sig = this.malloc(empty, this.rawSigLen)
        let pubkey = this.malloc(pubkeyBuf, this.pubkeyLen)
        let msg = this.malloc(msgBuf, this.msgLen)
        let isValid = false
        if (this.s._secp256k1_ecdsa_signature_parse_compact(this.ctx, sig, sigData) === 1) {
          isValid = this.s._secp256k1_ecdsa_verify(this.ctx, sig, msg, pubkey) === 1
        }
        this.cleanUp(sigData, sig, pubkey, msg)
        return isValid
      }

      secp256k1.recover = function (msg, sig, recid) {
        return this._recover(Buffer.from(msg), Buffer.from(sig), recid)
      }

      secp256k1._recover = function (msgBuf, sigBuf, recid) {
        if (isBuffer(msgBuf) !== true || msgBuf.length !== this.msgLen) {
          return false
        }
        if (isBuffer(sigBuf) !== true || sigBuf.length !== 64) {
          return false
        }
        if (typeof recid !== 'number' || recid > 1 || recid < 0) {
          return false
        }
        let empty = Buffer.from([])
        let msg = this.malloc(msgBuf, this.msgLen)
        let sigData = this.malloc(sigBuf, this.rawSigLen)
        let sig = this.malloc(empty, this.rawSigLen)
        let pubkey = this.malloc(empty, this.pubkeyLen)
        if (this.s._secp256k1_ecdsa_recoverable_signature_parse_compact(this.ctx, sig, sigData, recid) !== 1) {
          this.cleanUp(msg, sigData, sig, pubkey)
          return false
        }
        if (this.s._secp256k1_ecdsa_recover(this.ctx, pubkey, sig, msg) !== 1) {
          this.cleanUp(msg, sigData, sig, pubkey)
          return false
        }
        let pb = this.copyToBuffer(pubkey, this.pubkeyLen)
        this.cleanUp(msg, sigData, sig, pubkey)
        return pb
      }

      secp256k1.destroy = function () {
        this.s._secp256k1_context_destroy(this.ctx)
      }

      resolve(secp256k1)
    })
  })
}
