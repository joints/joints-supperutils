'use strict';

var extend = require('extend');

var dest     = './dest',
    src      = './src',
    test     = './test';

var config = {
  tasklines: {
    "default": {
      browserify: {
        bundleConfigs: [{
          entries: src + '/index.jsx',
          dest: dest + "/js",
          compress: true,
          outputName: 'supperutils.js',
          compressedOutputName: 'supperutils.min.js'
        }],
        extensions: ['.jsx', '.js'],
      }
    }
  }
}

module.exports = config;
