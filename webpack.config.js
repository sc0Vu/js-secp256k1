const webpack = require("webpack")
const path = require("path")
const UglifyPlugin = require('uglifyjs-webpack-plugin')

const nodeConfig = {
  mode: "development",
  target: 'node',
  context: path.resolve(__dirname, "."),
  entry: "./index-node.js",
  output: {
    libraryTarget: 'commonjs2',
    path: path.resolve(__dirname, "dist"),
    filename: "node-bundle.js"
  },
  module: {
    rules: [
      {
        test: /secp256k1-node\.wasm$/,
        type: "javascript/auto",
        loader: "wasm-loader",
      }
    ]
  }
}
const browserConfig = {
  mode: "development",
  target: 'web',
  context: path.resolve(__dirname, "."),
  entry: "./index-browser.js",
  output: {
    library: 'SECP256K1',
    libraryTarget: 'var',
    path: path.resolve(__dirname, "dist"),
    filename: "browser-bundle.js"
  },
  node: {
    fs: 'empty'
  },
  module: {
    rules: [
      {
        test: /secp256k1-browser\.wasm$/,
        type: "javascript/auto",
        loader: "wasm-loader",
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: [new UglifyPlugin({
      uglifyOptions: {
        output: {
          comments: false,
        },
      },
    })],
  }
}

module.exports = [ nodeConfig, browserConfig ]