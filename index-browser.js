const Secp256k1Wasm = require('./lib/secp256k1-browser.wasm')
const Secp256k1 = require('./lib/secp256k1-browser.js')
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
        let out = new Uint8Array(len)
        for (var i=0; i<len; i++) {
          let v = this.s.getValue(src + i, 'i8')
          out[i] = v
        }
        return out
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
        let privkey = this.s._malloc(this.privkeyLen)
        let msg = this.s._malloc(this.msgLen)
        this.s.HEAP8.set(privkeyBuf, privkey)
        this.s.HEAP8.set(msgBuf, msg)
        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privkey) !== 1) {
          this.s._free(privkey)
          this.s._free(msg)
          return false
        }
        let rawSig = this.s._malloc(this.sigLen)
        let sig = this.s._malloc(this.sigLen)
        let rec = this.s._malloc(1)
        if (this.s._secp256k1_ecdsa_sign_recoverable(this.ctx, rawSig, msg, privkey, null, null) !== 1) {
          this.s._free(privkey)
          this.s._free(msg)
          this.s._free(rawSig)
          this.s._free(sig)
          this.s._free(rec)
          return false
        }
        if (this.s._secp256k1_ecdsa_recoverable_signature_serialize_compact(this.ctx, sig, rec, rawSig) !== 1) {
          this.s._free(privkey)
          this.s._free(msg)
          this.s._free(rawSig)
          this.s._free(sig)
          this.s._free(rec)
          return false
        }
        // set rec to last
        let recid = this.s.getValue(rec, 'i8')
        let pe = this.copyToBuffer(sig, this.rawSigLen)
        this.s._free(privkey)
        this.s._free(msg)
        this.s._free(rawSig)
        this.s._free(sig)
        this.s._free(rec)
        return {
          signature: pe,
          recovery: recid
        }
      }

      secp256k1.serializePubkey = function (pubkey, compressed) {
        return this._serializePubkey(Buffer.from(pubkey), compressed)
      }

      secp256k1._serializePubkey = function (pubkeyBuf, compressed) {
        let pubkey = this.s._malloc(pubkeyBuf.length)
        let outputLen = this.s._malloc(1)
        let pubLen = (compressed) ? 33 : 65;
        let spubkey = this.s._malloc(pubLen)
        this.s.HEAP8.set(pubkeyBuf, pubkey)
        this.s.HEAP8.set([pubkeyBuf.length], outputLen)
        this.s.HEAP8.set([pubLen], outputLen)
        if (this.s._secp256k1_ec_pubkey_serialize(this.ctx, spubkey, outputLen, pubkey, (compressed) ? this.SECP256K1_EC_COMPRESSED : this.SECP256K1_EC_UNCOMPRESSED) !== 1) {
          this.s._free(pubkey)
          this.s._free(outputLen)
          this.s._free(spubkey)
          return false
        }
        let pc = this.copyToBuffer(spubkey, pubLen)
        this.s._free(pubkey)
        this.s._free(outputLen)
        this.s._free(spubkey)
        return pc
      }

      secp256k1.privkeyToPubkey = function (privkey) {
        return this._privkeyToPubkey(Buffer.from(privkey))
      }

      secp256k1._privkeyToPubkey = function (privkeyBuf) {
        if (isBuffer(privkeyBuf) !== true || privkeyBuf.length !== this.msgLen) {
          return false
        }
        // verify private key
        let privkey = this.s._malloc(this.privkeyLen)
        let pubkey = this.s._malloc(this.pubkeyLen)
        this.s.HEAP8.set(privkeyBuf, privkey)
        if (this.s._secp256k1_ec_seckey_verify(this.ctx, privkey) !== 1) {
          this.s._free(privkey)
          this.s._free(pubkey)
          return false
        }
        if (this.s._secp256k1_ec_pubkey_create(this.ctx, pubkey, privkey) !== 1) {
          this.s._free(privkey)
          this.s._free(pubkey)
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
        let sigData = this.s._malloc(this.rawSigLen)
        let sig = this.s._malloc(this.rawSigLen)
        let pubkey = this.s._malloc(this.pubkeyLen)
        let msg = this.s._malloc(this.msgLen)
        let isValid = false
        this.s.HEAP8.set(sigBuf, sigData)
        this.s.HEAP8.set(pubkeyBuf, pubkey)
        this.s.HEAP8.set(msgBuf, msg)
        if (this.s._secp256k1_ecdsa_signature_parse_compact(this.ctx, sig, sigData) === 1) {
          isValid = this.s._secp256k1_ecdsa_verify(this.ctx, sig, msg, pubkey) === 1
        }
        this.s._free(sigData)
        this.s._free(sig)
        this.s._free(pubkey)
        this.s._free(msg)
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
        let msg = this.s._malloc(this.msgLen)
        let sigData = this.s._malloc(this.rawSigLen)
        let sig = this.s._malloc(this.rawSigLen)
        let pubkey = this.s._malloc(this.pubkeyLen)
        this.s.HEAP8.set(msgBuf, msg)
        this.s.HEAP8.set(sigBuf, sigData)
        if (this.s._secp256k1_ecdsa_recoverable_signature_parse_compact(this.ctx, sig, sigData, recid) !== 1) {
          this.s._free(msg)
          this.s._free(sigData)
          this.s._free(sig)
          this.s._free(pubkey)
          return false
        }
        if (this.s._secp256k1_ecdsa_recover(this.ctx, pubkey, sig, msg) !== 1) {
          this.s._free(msg)
          this.s._free(sigData)
          this.s._free(sig)
          this.s._free(pubkey)
          return false
        }
        let pb = this.copyToBuffer(pubkey, this.pubkeyLen)
        this.s._free(msg)
        this.s._free(sigData)
        this.s._free(sig)
        this.s._free(pubkey)
        return pb
      }

      secp256k1.destroy = function () {
        this.s._secp256k1_context_destroy(this.ctx)
        // this.s = null
      }

      resolve(secp256k1)
    })
  })
}
