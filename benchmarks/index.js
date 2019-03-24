const benchmark = require('benchmark')
const keccakTinyAsync = require('../index')
const keccakjs = require('keccak')
const obindings = require('sha3')
const opurejs = require('js-sha3')

keccakTinyAsync().then(function (keccakTiny) {
  const emptyBuffer = new Buffer(0)
  new benchmark.Suite('Buffer 0bytes')
    .add('Keccak tiny (current)', () => keccakTiny.sha3_256(emptyBuffer).toString('hex'))
    .add('Pure JS (keccak)', () => keccakjs('sha3-256').update(emptyBuffer).digest('hex'))
    .add('Pure JS (sha3)', () => obindings.SHA3(256).update(emptyBuffer).digest('hex'))
    .add('Pure JS (js-sha3)', () => opurejs.keccak_256(emptyBuffer))
    .on('cycle', (event) => {
      console.log(String(event.target))
    })
    .on('complete', function () {
      console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
    })
    .run()

  const buffer10mib = require('crypto').randomBytes(10 * 1024 * 1024)
  new benchmark.Suite('Buffer 10MiB')
    .add('Keccak tiny (current)', () => keccakTiny.sha3_256(buffer10mib).toString('hex'))
    .add('Pure JS (keccak)', () => keccakjs('sha3-256').update(buffer10mib).digest('hex'))
    .add('Pure JS (sha3)', () => obindings.SHA3(256).update(buffer10mib).digest('hex'))
    .add('Pure JS (js-sha3)', () => opurejs.keccak_256(buffer10mib))
    .on('cycle', (event) => {
      console.log(String(event.target))
    })
    .on('complete', function () {
      console.log(`${this.name}: fastest is ${this.filter('fastest').map('name')}`)
    })
    .run()
})
