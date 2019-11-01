const assert = require('assert')
const { Builder, until } = require('selenium-webdriver')
const firefox = require('selenium-webdriver/firefox')
const path = require('path')

require('geckodriver')

describe('Secp256k1BrowserTest', function () {
  var driver

  beforeEach(async function () {
    const options = new firefox.Options()
    // options.addArguments('-headless')
    driver = new Builder().forBrowser('firefox')
      .setFirefoxOptions(options).build()
  })

  it ('Shoud hash message', async function () {
    try {
      const url = `file://${path.join(__dirname, 'index.html')}`
      await driver.get(url)
      await driver.wait(until.titleIs('Secp256k1 test succed'), 9000);
      assert(true)
    } catch (err) {
      assert(false)
    } finally {
      driver.quit()
    }
  })
})