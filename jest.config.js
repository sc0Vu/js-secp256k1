const config = {
  runner: 'jest-runner-mocha',
  notifyMode: 'success-change',
  coveragePathIgnorePatterns: [
    '/node_modules/', '**/src/', '**/lib/', '**/dist/'
  ],
  collectCoverage: true,
  coverageDirectory: './coverage/',
  coverageThreshold: {
      global: {
          functions: 80,
          lines: 80,
          statements: 80
      }
  },
  notify: true,
  clearMocks: true,
  resetMocks: true,
  resetModules: true,
  testMatch: ['**/tests/**Test.js'],
  bail: true
}

module.exports = config