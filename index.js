let secp256k1 = {}

secp256k1.node = require('./dist/node-bundle.js')
secp256k1.browser = require('./dist/browser-bundle.js')

module.exports = secp256k1