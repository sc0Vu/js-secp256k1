const webpack = require("webpack")
const path = require("path")
const nodeEnv = process.env.NODE_ENV
const nodeConfig = {
  mode: nodeEnv,
  target: 'node',
  context: path.resolve(__dirname, "."),
  entry: "./index.js",
  output: {
    library: 'SECP256K1',
    libraryTarget: 'commonjs2',
    path: path.resolve(__dirname, "dist"),
    filename: "node-bundle.js"
  },
  node: {
    fs: 'empty'
  },
  module: {
    rules: [
      {
        test: /secp256k1\.wasm$/,
        type: "javascript/auto",
        loader: "wasm-loader",
      }
    ]
  }
}

const browserConfig = {
  mode: nodeEnv,
  target: 'web',
  context: path.resolve(__dirname, "."),
  entry: "./index.js",
  output: {
    library: 'SECP256K1',
    libraryTarget: 'var',
    path: path.resolve(__dirname, "dist"),
    filename: "bundle.js"
  },
  node: {
    fs: 'empty'
  },
  module: {
    rules: [
      {
        test: /secp256k1\.wasm$/,
        type: "javascript/auto",
        loader: "wasm-loader",
      }
    ]
  }
}

module.exports = [ nodeConfig, browserConfig ]