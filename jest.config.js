const config = {
  runner: 'jest-runner-mocha',
  notifyMode: 'success-change',
  collectCoverage: false,
  notify: true,
  clearMocks: true,
  resetMocks: true,
  resetModules: true,
  testMatch: ['**/tests/**Test.js'],
  bail: true
}

module.exports = config