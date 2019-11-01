const Secp256k1Wasm = require('./lib/secp256k1-node.wasm')
const Secp256k1 = require('./lib/secp256k1-node.js')
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
        sigLen: {
          writable: false,
          value: 65
        }
      })

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
        let pe = new Buffer(this.sigLen-1)
        for (var i=0; i<64; i++) {
            var v = this.s.getValue(sig + i, 'i8')
            pe[i] = v
        }
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

      secp256k1.destroy = function () {
        this.s._secp256k1_context_destroy(this.ctx)
        // this.s = null
      }

      resolve(secp256k1)
    })
  })
}
