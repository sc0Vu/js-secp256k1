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
        serializedPubkeyLen: {
          writable: false,
          value: 65
        },
        SECP256K1_EC_COMPRESSED: {
          writable: false,
          value: 258
        },
        SECP256K1_EC_UNCOMPRESSED: {
          writable: false,
          value: 2
        },
        MAX_COMBINE_PUBKEYS: {
          writable: false,
          value: 256
        },
      })

      const empty = Buffer.from([])

      // Reused memory allocations, these live as long as the object
      const publicKeyScratch = secp256k1.s._malloc(secp256k1.pubkeyLen)
      const serializedPublicKeyScratch = secp256k1.s._malloc(secp256k1.serializedPubkeyLen)
      const lengthScratch = secp256k1.s._malloc(1)
      const privateKeyScratch = secp256k1.s._malloc(secp256k1.privkeyLen)
      const tweakScratch = secp256k1.s._malloc(secp256k1.privkeyLen)
      const rawSignatureScratch = secp256k1.s._malloc(secp256k1.sigLen)
      const signatureScratch = secp256k1.s._malloc(secp256k1.sigLen)
      const signatureDataScratch = secp256k1.s._malloc(secp256k1.sigLen)
      const messageScratch = secp256k1.s._malloc(secp256k1.msgLen)
      const rec = secp256k1.s._malloc(1)

      const combineScratch = secp256k1.s._malloc(secp256k1.MAX_COMBINE_PUBKEYS * secp256k1.pubkeyLen)

      const combinePtr = []
      for (let idx = 0; idx < secp256k1.MAX_COMBINE_PUBKEYS; idx++) {
        combinePtr.push(combineScratch + idx * secp256k1.pubkeyLen);
      }
      const combinePtrScratch = secp256k1.s._malloc(secp256k1.MAX_COMBINE_PUBKEYS * 4)
      secp256k1.s.HEAP32.set(combinePtr, combinePtrScratch >> 2)

      secp256k1.copyToBuffer = function (src, len) {
        let out = new Buffer(len)
        for (var i=0; i<len; i++) {
          let v = this.s.getValue(src + i, 'i8')
          out[i] = v
        }
        return out
      }

      secp256k1.copyFromBuffer = function (buf, dst) {
        this.s.HEAP8.set(buf, dst)
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
        this.copyFromBuffer(privkeyBuf, privateKeyScratch)
        this.copyFromBuffer(msgBuf, messageScratch)

        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privateKeyScratch) !== 1) {
          return false
        }

        if (this.s._secp256k1_ecdsa_sign_recoverable(this.ctx, rawSignatureScratch, messageScratch, privateKeyScratch, null, null) !== 1) {
          return false
        }

        if (this.s._secp256k1_ecdsa_recoverable_signature_serialize_compact(this.ctx, signatureScratch, rec, rawSignatureScratch) !== 1) {
          return false
        }

        // set rec to last
        let recid = this.s.getValue(rec, 'i8')
        let pe = this.copyToBuffer(signatureScratch, this.rawSigLen)

        return {
          signature: pe,
          recovery: recid
        }
      }

      secp256k1.combinePubkeys = function(pubkeyArr) {
        return this._combinePubkeys(pubkeyArr.map(Buffer.from))
      }

      secp256k1._combinePubkeys = function(pubkeyBufArr) {
        if (pubkeyBufArr.length > this.MAX_COMBINE_PUBKEYS) {
          return false
        }

        pubkeyBufArr.forEach((pubkeyBuf, idx) => {
          this.copyFromBuffer(pubkeyBuf, combineScratch + idx * this.pubkeyLen);
        })

        if(this.s._secp256k1_ec_pubkey_combine(this.ctx, publicKeyScratch, combinePtrScratch, pubkeyBufArr.length) !== 1) {
          return false
        }

        const pb = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return pb
      }

      secp256k1.serializePubkey = function (pubkey, compressed) {
        return this._serializePubkey(Buffer.from(pubkey), compressed)
      }

      secp256k1._serializePubkey = function (pubkeyBuf, compressed) {
        let pubLen = (compressed) ? 33 : 65;
        let mode = (compressed) ? this.SECP256K1_EC_COMPRESSED : this.SECP256K1_EC_UNCOMPRESSED

        this.copyFromBuffer(pubkeyBuf, publicKeyScratch)
        this.s.HEAP32.set([pubLen], lengthScratch >> 2)

        if (this.s._secp256k1_ec_pubkey_serialize(this.ctx, serializedPublicKeyScratch, lengthScratch, publicKeyScratch, mode) !== 1) {
          return false
        }
        let pc = this.copyToBuffer(serializedPublicKeyScratch, pubLen)
        return pc
      }

      secp256k1.parsePubkey = function (serializedPubkey) {
        return this._parsePubkey(Buffer.from(serializedPubkey))
      }

      secp256k1._parsePubkey = function (serializedPubkeyBuf) {
        this.copyFromBuffer(serializedPubkeyBuf, serializedPublicKeyScratch)
        // this.s.HEAP32.set([serializedPubkeyBuf.length], lengthScratch >> 2)

        if (this.s._secp256k1_ec_pubkey_parse(this.ctx, publicKeyScratch, serializedPublicKeyScratch, serializedPubkeyBuf.length) !== 1) {
          return false;
        }

        let pc = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return pc
      }

      secp256k1.privkeyAddTweak = function (privkey, tweak) {
        return this._privkeyAddTweak(Buffer.from(privkey), Buffer.from(tweak))
      }

      secp256k1._privkeyAddTweak = function (privkeyBuf, tweakBuf) {
        this.copyFromBuffer(privkeyBuf, privateKeyScratch)
        this.copyFromBuffer(tweakBuf, tweakScratch)

        if (this.s._secp256k1_ec_seckey_tweak_add(this.ctx, privateKeyScratch, tweakScratch) !== 1) {
          return false
        }

        const tweakedPrivkey = this.copyToBuffer(privateKeyScratch, this.privkeyLen)
        return tweakedPrivkey
      }

      secp256k1.privkeyMulTweak = function (privkey, tweak) {
        return this._privkeyMulTweak(Buffer.from(privkey), Buffer.from(tweak))
      }

      secp256k1._privkeyMulTweak = function (privkeyBuf, tweakBuf) {
        this.copyFromBuffer(privkeyBuf, privateKeyScratch)
        this.copyFromBuffer(tweakBuf, tweakScratch)

        if (this.s._secp256k1_ec_seckey_tweak_mul(this.ctx, privateKeyScratch, tweakScratch) !== 1) {
          return false
        }

        const tweakedPrivkey = this.copyToBuffer(privateKeyScratch, this.privkeyLen)
        return tweakedPrivkey
      }

      secp256k1.privkeyNegate = function (privkey) {
        return this._privkeyNegate(Buffer.from(privkey))
      }

      secp256k1._privkeyNegate = function (privkeyBuf) {
        this.copyFromBuffer(privkeyBuf, privateKeyScratch);

        if (this.s._secp256k1_ec_seckey_negate(this.ctx, privateKeyScratch) !== 1) {
          return false
        }

        return this.copyToBuffer(privateKeyScratch, this.privkeyLen)
      }

      secp256k1.privkeyVerify = function (privkey) {
        return this._privkeyVerify(Buffer.from(privkey))
      }

      secp256k1._privkeyVerify = function (privkeyBuf) {
        this.copyFromBuffer(privkeyBuf, privateKeyScratch)

        return this.s._secp256k1_ec_seckey_verify(this.ctx, privateKeyScratch) === 1
      }

      secp256k1.privkeyToPubkey = function (privkey) {
        return this._privkeyToPubkey(Buffer.from(privkey))
      }

      secp256k1._privkeyToPubkey = function (privkeyBuf) {
        // if (isBuffer(privkeyBuf) !== true || privkeyBuf.length !== this.privkeyLen) {
        //   return false
        // }
        this.copyFromBuffer(privkeyBuf, privateKeyScratch)

        // verify private key
        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privateKeyScratch) !== 1) {
          return false
        }

        if (this.s._secp256k1_ec_pubkey_create(this.ctx, publicKeyScratch, privateKeyScratch) !== 1) {
          return false
        }

        let pb = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return pb
      }

      secp256k1.pubkeyMulTweak = function (pubkey, tweak) {
        return secp256k1._pubkeyMulTweak(Buffer.from(pubkey), Buffer.from(tweak))
      }

      secp256k1._pubkeyMulTweak = function (pubkeyBuf, tweakBuf) {
        this.copyFromBuffer(pubkeyBuf, publicKeyScratch)
        this.copyFromBuffer(tweakBuf, tweakScratch)

        if (this.s._secp256k1_ec_pubkey_tweak_mul(this.ctx, publicKeyScratch, tweakScratch) !== 1) {
          return false
        }

        const tweakedPubkey = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return tweakedPubkey
      }

      secp256k1.pubkeyNegate = function (pubkey) {
        return this._pubkeyNegate(Buffer.from(pubkey))
      }

      secp256k1._pubkeyNegate = function (pubkeyBuf) {
        this.copyFromBuffer(pubkeyBuf, publicKeyScratch)

        this.s._secp256k1_ec_pubkey_negate(this.ctx, publicKeyScratch)

        const negatedPubkey = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return negatedPubkey
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
        this.copyFromBuffer(sigBuf, signatureDataScratch)
        this.copyFromBuffer(pubkeyBuf, publicKeyScratch)
        this.copyFromBuffer(msgBuf, messageScratch)
        let isValid = false
        if (this.s._secp256k1_ecdsa_signature_parse_compact(this.ctx, signatureScratch, signatureDataScratch) === 1) {
          isValid = this.s._secp256k1_ecdsa_verify(this.ctx, signatureScratch, messageScratch, publicKeyScratch) === 1
        }
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
        this.copyFromBuffer(msgBuf, messageScratch)
        this.copyFromBuffer(sigBuf, signatureDataScratch)

        if (this.s._secp256k1_ecdsa_recoverable_signature_parse_compact(this.ctx, signatureScratch, signatureDataScratch, recid) !== 1) {
          return false
        }

        if (this.s._secp256k1_ecdsa_recover(this.ctx, publicKeyScratch, signatureScratch, messageScratch) !== 1) {
          return false
        }

        let pb = this.copyToBuffer(publicKeyScratch, this.pubkeyLen)
        return pb
      }

      secp256k1.destroy = function () {
        this.s._secp256k1_context_destroy(this.ctx)
      }

      resolve(secp256k1)
    })
  })
}
