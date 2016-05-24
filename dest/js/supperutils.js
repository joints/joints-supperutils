(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/*
 * JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*global unescape, define, module */

;(function ($) {
  'use strict'

  /*
  * Add integers, wrapping at 2^32. This uses 16-bit operations internally
  * to work around bugs in some JS interpreters.
  */
  function safe_add (x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF)
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
    return (msw << 16) | (lsw & 0xFFFF)
  }

  /*
  * Bitwise rotate a 32-bit number to the left.
  */
  function bit_rol (num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt))
  }

  /*
  * These functions implement the four basic operations the algorithm uses.
  */
  function md5_cmn (q, a, b, x, s, t) {
    return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b)
  }
  function md5_ff (a, b, c, d, x, s, t) {
    return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t)
  }
  function md5_gg (a, b, c, d, x, s, t) {
    return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t)
  }
  function md5_hh (a, b, c, d, x, s, t) {
    return md5_cmn(b ^ c ^ d, a, b, x, s, t)
  }
  function md5_ii (a, b, c, d, x, s, t) {
    return md5_cmn(c ^ (b | (~d)), a, b, x, s, t)
  }

  /*
  * Calculate the MD5 of an array of little-endian words, and a bit length.
  */
  function binl_md5 (x, len) {
    /* append padding */
    x[len >> 5] |= 0x80 << (len % 32)
    x[(((len + 64) >>> 9) << 4) + 14] = len

    var i
    var olda
    var oldb
    var oldc
    var oldd
    var a = 1732584193
    var b = -271733879
    var c = -1732584194
    var d = 271733878

    for (i = 0; i < x.length; i += 16) {
      olda = a
      oldb = b
      oldc = c
      oldd = d

      a = md5_ff(a, b, c, d, x[i], 7, -680876936)
      d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586)
      c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819)
      b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330)
      a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897)
      d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426)
      c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341)
      b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983)
      a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416)
      d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417)
      c = md5_ff(c, d, a, b, x[i + 10], 17, -42063)
      b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162)
      a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682)
      d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101)
      c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290)
      b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329)

      a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510)
      d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632)
      c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713)
      b = md5_gg(b, c, d, a, x[i], 20, -373897302)
      a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691)
      d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083)
      c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335)
      b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848)
      a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438)
      d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690)
      c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961)
      b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501)
      a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467)
      d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784)
      c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473)
      b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734)

      a = md5_hh(a, b, c, d, x[i + 5], 4, -378558)
      d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463)
      c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562)
      b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556)
      a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060)
      d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353)
      c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632)
      b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640)
      a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174)
      d = md5_hh(d, a, b, c, x[i], 11, -358537222)
      c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979)
      b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189)
      a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487)
      d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835)
      c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520)
      b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651)

      a = md5_ii(a, b, c, d, x[i], 6, -198630844)
      d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415)
      c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905)
      b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055)
      a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571)
      d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606)
      c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523)
      b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799)
      a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359)
      d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744)
      c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380)
      b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649)
      a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070)
      d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379)
      c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259)
      b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551)

      a = safe_add(a, olda)
      b = safe_add(b, oldb)
      c = safe_add(c, oldc)
      d = safe_add(d, oldd)
    }
    return [a, b, c, d]
  }

  /*
  * Convert an array of little-endian words to a string
  */
  function binl2rstr (input) {
    var i
    var output = ''
    for (i = 0; i < input.length * 32; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF)
    }
    return output
  }

  /*
  * Convert a raw string to an array of little-endian words
  * Characters >255 have their high-byte silently ignored.
  */
  function rstr2binl (input) {
    var i
    var output = []
    output[(input.length >> 2) - 1] = undefined
    for (i = 0; i < output.length; i += 1) {
      output[i] = 0
    }
    for (i = 0; i < input.length * 8; i += 8) {
      output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32)
    }
    return output
  }

  /*
  * Calculate the MD5 of a raw string
  */
  function rstr_md5 (s) {
    return binl2rstr(binl_md5(rstr2binl(s), s.length * 8))
  }

  /*
  * Calculate the HMAC-MD5, of a key and some data (raw strings)
  */
  function rstr_hmac_md5 (key, data) {
    var i
    var bkey = rstr2binl(key)
    var ipad = []
    var opad = []
    var hash
    ipad[15] = opad[15] = undefined
    if (bkey.length > 16) {
      bkey = binl_md5(bkey, key.length * 8)
    }
    for (i = 0; i < 16; i += 1) {
      ipad[i] = bkey[i] ^ 0x36363636
      opad[i] = bkey[i] ^ 0x5C5C5C5C
    }
    hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8)
    return binl2rstr(binl_md5(opad.concat(hash), 512 + 128))
  }

  /*
  * Convert a raw string to a hex string
  */
  function rstr2hex (input) {
    var hex_tab = '0123456789abcdef'
    var output = ''
    var x
    var i
    for (i = 0; i < input.length; i += 1) {
      x = input.charCodeAt(i)
      output += hex_tab.charAt((x >>> 4) & 0x0F) +
      hex_tab.charAt(x & 0x0F)
    }
    return output
  }

  /*
  * Encode a string as utf-8
  */
  function str2rstr_utf8 (input) {
    return unescape(encodeURIComponent(input))
  }

  /*
  * Take string arguments and return either raw or hex encoded strings
  */
  function raw_md5 (s) {
    return rstr_md5(str2rstr_utf8(s))
  }
  function hex_md5 (s) {
    return rstr2hex(raw_md5(s))
  }
  function raw_hmac_md5 (k, d) {
    return rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))
  }
  function hex_hmac_md5 (k, d) {
    return rstr2hex(raw_hmac_md5(k, d))
  }

  function md5 (string, key, raw) {
    if (!key) {
      if (!raw) {
        return hex_md5(string)
      }
      return raw_md5(string)
    }
    if (!raw) {
      return hex_hmac_md5(key, string)
    }
    return raw_hmac_md5(key, string)
  }

  if (typeof define === 'function' && define.amd) {
    define(function () {
      return md5
    })
  } else if (typeof module === 'object' && module.exports) {
    module.exports = md5
  } else {
    $.md5 = md5
  }
}(this))

},{}],2:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = setTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    clearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        setTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],3:[function(require,module,exports){
/**
 * @preserve jquery-param (c) 2015 KNOWLEDGECODE | MIT
 */
(function (global) {
    'use strict';

    var param = function (a) {
        var s = [], rbracket = /\[\]$/,
            isArray = function (obj) {
                return Object.prototype.toString.call(obj) === '[object Array]';
            }, add = function (k, v) {
                v = typeof v === 'function' ? v() : v === null ? '' : v === undefined ? '' : v;
                s[s.length] = encodeURIComponent(k) + '=' + encodeURIComponent(v);
            }, buildParams = function (prefix, obj) {
                var i, len, key;

                if (prefix) {
                    if (isArray(obj)) {
                        for (i = 0, len = obj.length; i < len; i++) {
                            if (rbracket.test(prefix)) {
                                add(prefix, obj[i]);
                            } else {
                                buildParams(prefix + '[' + (typeof obj[i] === 'object' ? i : '') + ']', obj[i]);
                            }
                        }
                    } else if (obj && String(obj) === '[object Object]') {
                        for (key in obj) {
                            buildParams(prefix + '[' + key + ']', obj[key]);
                        }
                    } else {
                        add(prefix, obj);
                    }
                } else if (isArray(obj)) {
                    for (i = 0, len = obj.length; i < len; i++) {
                        add(obj[i].name, obj[i].value);
                    }
                } else {
                    for (key in obj) {
                        buildParams(key, obj[key]);
                    }
                }
                return s;
            };

        return buildParams('', a).join('&').replace(/%20/g, '+');
    };

    if (typeof module === 'object' && typeof module.exports === 'object') {
        module.exports = param;
    } else if (typeof define === 'function' && define.amd) {
        define([], function () {
            return param;
        });
    } else {
        global.param = param;
    }

}(this));


},{}],4:[function(require,module,exports){
'use strict';
/* eslint-disable no-unused-vars */
var hasOwnProperty = Object.prototype.hasOwnProperty;
var propIsEnumerable = Object.prototype.propertyIsEnumerable;

function toObject(val) {
	if (val === null || val === undefined) {
		throw new TypeError('Object.assign cannot be called with null or undefined');
	}

	return Object(val);
}

function shouldUseNative() {
	try {
		if (!Object.assign) {
			return false;
		}

		// Detect buggy property enumeration order in older V8 versions.

		// https://bugs.chromium.org/p/v8/issues/detail?id=4118
		var test1 = new String('abc');  // eslint-disable-line
		test1[5] = 'de';
		if (Object.getOwnPropertyNames(test1)[0] === '5') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test2 = {};
		for (var i = 0; i < 10; i++) {
			test2['_' + String.fromCharCode(i)] = i;
		}
		var order2 = Object.getOwnPropertyNames(test2).map(function (n) {
			return test2[n];
		});
		if (order2.join('') !== '0123456789') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test3 = {};
		'abcdefghijklmnopqrst'.split('').forEach(function (letter) {
			test3[letter] = letter;
		});
		if (Object.keys(Object.assign({}, test3)).join('') !==
				'abcdefghijklmnopqrst') {
			return false;
		}

		return true;
	} catch (e) {
		// We don't expect any of the above to throw, but better to be safe.
		return false;
	}
}

module.exports = shouldUseNative() ? Object.assign : function (target, source) {
	var from;
	var to = toObject(target);
	var symbols;

	for (var s = 1; s < arguments.length; s++) {
		from = Object(arguments[s]);

		for (var key in from) {
			if (hasOwnProperty.call(from, key)) {
				to[key] = from[key];
			}
		}

		if (Object.getOwnPropertySymbols) {
			symbols = Object.getOwnPropertySymbols(from);
			for (var i = 0; i < symbols.length; i++) {
				if (propIsEnumerable.call(from, symbols[i])) {
					to[symbols[i]] = from[symbols[i]];
				}
			}
		}
	}

	return to;
};

},{}],5:[function(require,module,exports){
(function (process){
/*
 * PinkySwear.js 2.2.2 - Minimalistic implementation of the Promises/A+ spec
 * 
 * Public Domain. Use, modify and distribute it any way you like. No attribution required.
 *
 * NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.
 *
 * PinkySwear is a very small implementation of the Promises/A+ specification. After compilation with the
 * Google Closure Compiler and gzipping it weighs less than 500 bytes. It is based on the implementation for 
 * Minified.js and should be perfect for embedding. 
 *
 *
 * PinkySwear has just three functions.
 *
 * To create a new promise in pending state, call pinkySwear():
 *         var promise = pinkySwear();
 *
 * The returned object has a Promises/A+ compatible then() implementation:
 *          promise.then(function(value) { alert("Success!"); }, function(value) { alert("Failure!"); });
 *
 *
 * The promise returned by pinkySwear() is a function. To fulfill the promise, call the function with true as first argument and
 * an optional array of values to pass to the then() handler. By putting more than one value in the array, you can pass more than one
 * value to the then() handlers. Here an example to fulfill a promsise, this time with only one argument: 
 *         promise(true, [42]);
 *
 * When the promise has been rejected, call it with false. Again, there may be more than one argument for the then() handler:
 *         promise(true, [6, 6, 6]);
 *         
 * You can obtain the promise's current state by calling the function without arguments. It will be true if fulfilled,
 * false if rejected, and otherwise undefined.
 * 		   var state = promise(); 
 * 
 * https://github.com/timjansen/PinkySwear.js
 */
(function(target) {
	var undef;

	function isFunction(f) {
		return typeof f == 'function';
	}
	function isObject(f) {
		return typeof f == 'object';
	}
	function defer(callback) {
		if (typeof setImmediate != 'undefined')
			setImmediate(callback);
		else if (typeof process != 'undefined' && process['nextTick'])
			process['nextTick'](callback);
		else
			setTimeout(callback, 0);
	}

	target[0][target[1]] = function pinkySwear(extend) {
		var state;           // undefined/null = pending, true = fulfilled, false = rejected
		var values = [];     // an array of values as arguments for the then() handlers
		var deferred = [];   // functions to call when set() is invoked

		var set = function(newState, newValues) {
			if (state == null && newState != null) {
				state = newState;
				values = newValues;
				if (deferred.length)
					defer(function() {
						for (var i = 0; i < deferred.length; i++)
							deferred[i]();
					});
			}
			return state;
		};

		set['then'] = function (onFulfilled, onRejected) {
			var promise2 = pinkySwear(extend);
			var callCallbacks = function() {
	    		try {
	    			var f = (state ? onFulfilled : onRejected);
	    			if (isFunction(f)) {
		   				function resolve(x) {
						    var then, cbCalled = 0;
		   					try {
				   				if (x && (isObject(x) || isFunction(x)) && isFunction(then = x['then'])) {
										if (x === promise2)
											throw new TypeError();
										then['call'](x,
											function() { if (!cbCalled++) resolve.apply(undef,arguments); } ,
											function(value){ if (!cbCalled++) promise2(false,[value]);});
				   				}
				   				else
				   					promise2(true, arguments);
		   					}
		   					catch(e) {
		   						if (!cbCalled++)
		   							promise2(false, [e]);
		   					}
		   				}
		   				resolve(f.apply(undef, values || []));
		   			}
		   			else
		   				promise2(state, values);
				}
				catch (e) {
					promise2(false, [e]);
				}
			};
			if (state != null)
				defer(callCallbacks);
			else
				deferred.push(callCallbacks);
			return promise2;
		};
        if(extend){
            set = extend(set);
        }
		return set;
	};
})(typeof module == 'undefined' ? [window, 'pinkySwear'] : [module, 'exports']);


}).call(this,require('_process'))
},{"_process":2}],6:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isDescendant = isDescendant;
exports.offset = offset;
exports.forceRedraw = forceRedraw;
exports.withoutTransition = withoutTransition;
exports.getOuterHeight = getOuterHeight;
exports.getScrollTop = getScrollTop;
exports.overView = overView;
exports.computedStyle = computedStyle;
exports.getLineHeight = getLineHeight;
exports.onEvent = onEvent;
exports.offEvent = offEvent;
exports.onceEvent = onceEvent;
function tryParseInt(p) {
  if (!p) {
    return 0;
  }
  var pi = parseInt(p);
  return pi || 0;
}

function isDescendant(parent, child) {
  var node = child.parentNode;

  while (node !== null) {
    if (node === parent) {
      return true;
    }
    node = node.parentNode;
  }

  return false;
}

function offset(el) {
  var rect = el.getBoundingClientRect();
  return {
    top: rect.top + document.body.scrollTop,
    left: rect.left + document.body.scrollLeft
  };
}

function forceRedraw(el) {
  var originalDisplay = el.style.display;

  el.style.display = 'none';
  var oh = el.offsetHeight;
  el.style.display = originalDisplay;
  return oh;
}

function withoutTransition(el, callback) {
  //turn off transition
  el.style.transition = 'none';

  callback();

  //force a redraw
  forceRedraw(el);

  //put the transition back
  el.style.transition = '';
}

function getOuterHeight(el) {
  var height = el.clientHeight + tryParseInt(el.style.borderTopWidth) + tryParseInt(el.style.borderBottomWidth) + tryParseInt(el.style.marginTop) + tryParseInt(el.style.marginBottom);
  return height;
}

function getScrollTop() {
  var dd = document.documentElement;
  var scrollTop = 0;
  if (dd && dd.scrollTop) {
    scrollTop = dd.scrollTop;
  } else if (document.body) {
    scrollTop = document.body.scrollTop;
  }
  return scrollTop;
}

function overView(el) {
  var pad = arguments.length <= 1 || arguments[1] === undefined ? 0 : arguments[1];

  var height = window.innerHeight || document.documentElement.clientHeight;

  var bottom = el.getBoundingClientRect().bottom + pad;
  return bottom > height;
}

function computedStyle(el, attr) {
  var lineHeight;
  if (el.currentStyle) {
    lineHeight = el.currentStyle[attr];
  } else if (window.getComputedStyle) {
    lineHeight = window.getComputedStyle(el, null)[attr];
  }
  return lineHeight;
}

function getLineHeight(origin) {
  var el = origin.cloneNode(true);
  var lineHeight = void 0;
  el.style.padding = 0;
  el.rows = 1;
  el.innerHTML = '&nbsp;';
  el.style.minHeight = 'inherit';
  origin.parentNode.appendChild(el);
  lineHeight = el.clientHeight;
  origin.parentNode.removeChild(el);

  return lineHeight;
}

// dom事件绑定
function onEvent(el, type, callback) {
  if (el.addEventListener) {
    el.addEventListener(type, callback);
  } else {
    el.attachEvent('on' + type, function () {
      callback.call(el);
    });
  }

  return callback;
}

// dom事件去除
function offEvent(el, type, callback) {
  if (el.removeEventListener) {
    el.removeEventListener(type, callback);
  } else {
    el.detachEvent('on' + type, callback);
  }

  return callback;
}

// 单次dom事件绑定
function onceEvent(el, type, callback) {
  var typeArray = type.split(' ');
  var recursiveFunction = function recursiveFunction(e) {
    e.target.removeEventListener(e.type, recursiveFunction);
    return callback(e);
  };

  for (var i = typeArray.length - 1; i >= 0; i--) {
    on(el, typeArray[i], recursiveFunction);
  }
}

exports.default = {
  onEvent: onEvent, offEvent: offEvent, onceEvent: onceEvent
};

},{}],7:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.clone = clone;
exports.addDays = addDays;
exports.addMonths = addMonths;
exports.getFirstDayOfMonth = getFirstDayOfMonth;
exports.getDaysInMonth = getDaysInMonth;
exports.getWeekArray = getWeekArray;
exports.isEqualDate = isEqualDate;
exports.isEqual = isEqual;
exports.monthDiff = monthDiff;
exports.format = format;
function clone(d) {
  return new Date(d.getTime());
}

function addDays(d, days) {
  var newDate = clone(d);
  newDate.setDate(d.getDate() + days);
  return newDate;
}

function addMonths(d, months) {
  var newDate = clone(d);
  newDate.setMonth(d.getMonth() + months);
  return newDate;
}

function getFirstDayOfMonth(d) {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}

function getDaysInMonth(d) {
  var resultDate = getFirstDayOfMonth(d);

  resultDate.setMonth(resultDate.getMonth() + 1);
  resultDate.setDate(resultDate.getDate() - 1);

  return resultDate.getDate();
}

function getWeekArray(d) {
  var dayArray = [];
  var daysInMonth = getDaysInMonth(d);
  var daysInWeek = void 0;
  var emptyDays = void 0;
  var firstDayOfWeek = void 0;
  var week = void 0;
  var weekArray = [];

  for (var i = 1; i <= daysInMonth; i++) {
    dayArray.push(new Date(d.getFullYear(), d.getMonth(), i));
  }

  while (dayArray.length) {
    firstDayOfWeek = dayArray[0].getDay();
    daysInWeek = 7 - firstDayOfWeek;
    emptyDays = 7 - daysInWeek;
    week = dayArray.splice(0, daysInWeek);

    for (var j = 0; j < emptyDays; j++) {
      week.unshift(null);
    }

    weekArray.push(week);
  }

  return weekArray;
}

function isEqualDate(d1, d2) {
  if (!d1 || !d2 || !(d1 instanceof Date) || !(d2 instanceof Date)) {
    return false;
  }

  return d1 && d2 && d1.getFullYear() === d2.getFullYear() && d1.getMonth() === d2.getMonth() && d1.getDate() === d2.getDate();
}

function isEqual(d1, d2) {
  if (!d1 || !d2 || !(d1 instanceof Date) || !(d2 instanceof Date)) {
    return false;
  }

  return d1.getTime() === d2.getTime();
}

function monthDiff(d1, d2) {
  var m = void 0;
  m = (d1.getFullYear() - d2.getFullYear()) * 12;
  m += d1.getMonth();
  m -= d2.getMonth();
  return m;
}

function format(date, fmt) {
  if (!date) {
    return '';
  }
  if (!(date instanceof Date)) {
    date = convert(date);
  }

  if (isNaN(date.getTime())) {
    return 'Invalid Date';
  }

  var o = {
    'M+': date.getMonth() + 1,
    'd+': date.getDate(),
    'h+': date.getHours(),
    'm+': date.getMinutes(),
    's+': date.getSeconds(),
    'q+': Math.floor((date.getMonth() + 3) / 3),
    'S': date.getMilliseconds()
  };
  if (/(y+)/.test(fmt)) {
    fmt = fmt.replace(RegExp.$1, (date.getFullYear() + '').substr(4 - RegExp.$1.length));
  }
  for (var k in o) {
    if (new RegExp('(' + k + ')').test(fmt)) {
      fmt = fmt.replace(RegExp.$1, RegExp.$1.length === 1 ? o[k] : ('00' + o[k]).substr(('' + o[k]).length));
    }
  }
  return fmt;
}

},{}],8:[function(require,module,exports){
'use strict';

var _refetch = require('./refetch');

var _refetch2 = _interopRequireDefault(_refetch);

var _dom = require('./dom');

var Dom = _interopRequireWildcard(_dom);

var _dt = require('./dt');

var Dt = _interopRequireWildcard(_dt);

var _obj = require('./obj');

var Obj = _interopRequireWildcard(_obj);

var _regex = require('./regex');

var Regex = _interopRequireWildcard(_regex);

var _str = require('./str');

var Str = _interopRequireWildcard(_str);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

module.exports = {
  Refetch: _refetch2.default,
  Dom: Dom,
  Dt: Dt,
  Obj: Obj,
  Regex: Regex,
  Str: Str
};

},{"./dom":6,"./dt":7,"./obj":9,"./refetch":12,"./regex":16,"./str":17}],9:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.deepEqual = undefined;

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; }; /**
                                                                                                                                                                                                                                                   * 对象相关方法
                                                                                                                                                                                                                                                   * 
                                                                                                                                                                                                                                                   * Created by Ray on 2015-09-05
                                                                                                                                                                                                                                                   *
                                                                                                                                                                                                                                                   * 描述：用于定义自定义错误
                                                                                                                                                                                                                                                   */

exports.isEmpty = isEmpty;
exports.forEach = forEach;
exports.toTextValue = toTextValue;
exports.hashcode = hashcode;
exports.sortByKey = sortByKey;
exports.shallowEqual = shallowEqual;
exports.type = type;
exports.merge = merge;
exports.clone = clone;

var _str = require('./str');

var deepEqual = exports.deepEqual = function compare(x, y) {
  var p = void 0;

  // remember that NaN === NaN returns false
  // and isNaN(undefined) returns true
  if (isNaN(x) && isNaN(y) && typeof x === 'number' && typeof y === 'number') {
    return true;
  }

  // Compare primitives and functions.
  // Check if both arguments link to the same object.
  // Especially useful on step when comparing prototypes
  if (x === y) {
    return true;
  }

  // Works in case when functions are created in constructor.
  // Comparing dates is a common scenario. Another built-ins?
  // We can even handle functions passed across iframes
  if (typeof x === 'function' && typeof y === 'function' || x instanceof RegExp && y instanceof RegExp || x instanceof String || y instanceof String || x instanceof Number || y instanceof Number) {
    return x.toString() === y.toString();
  }

  if (x instanceof Date && y instanceof Date) {
    return x.getTime() === y.getTime();
  }

  // At last checking prototypes as good a we can
  if (!(x instanceof Object && y instanceof Object)) {
    return false;
  }

  if (x.prototype !== y.prototype) {
    return false;
  }

  if (x.constructor !== y.constructor) {
    return false;
  }

  for (p in y) {
    if (!x.hasOwnProperty(p)) {
      return false;
      //}
      //else if (typeof y[p] !== typeof x[p]) {
      //  return false;
    }
  }

  for (p in x) {
    if (!y.hasOwnProperty(p)) {
      return false;
    }

    if (_typeof(y[p]) !== _typeof(x[p])) {
      return false;
    }

    if (!compare(x[p], y[p])) {
      return false;
    }
  }

  return true;
};

function isEmpty(obj) {
  // null and undefined are "empty"
  if (obj === null || obj === undefined) {
    return true;
  }

  if (typeof obj === 'number' && isNaN(obj)) {
    return true;
  }

  if (obj.length !== undefined) {
    return obj.length === 0;
  }

  if (obj instanceof Date) {
    return false;
  }

  if ((typeof obj === 'undefined' ? 'undefined' : _typeof(obj)) === 'object') {
    return Object.keys(obj).length === 0;
  }

  return false;
}

function forEach(obj, fn, context) {
  Object.keys(obj).forEach(function (key) {
    return fn.call(context, obj[key], key);
  });
}

function toTextValue(arr) {
  var textTpl = arguments.length <= 1 || arguments[1] === undefined ? '{text}' : arguments[1];
  var valueTpl = arguments.length <= 2 || arguments[2] === undefined ? '{id}' : arguments[2];

  if (!arr) {
    return [];
  }
  if (!Array.isArray(arr)) {
    arr = Object.keys(arr).map(function (key) {
      return {
        id: key,
        text: arr[key]
      };
    });
  }
  arr = arr.map(function (s) {
    if ((typeof s === 'undefined' ? 'undefined' : _typeof(s)) !== 'object') {
      s = s.toString();
      return { $text: s, $value: s, $key: hashcode(s) };
    } else {
      s.$text = (0, _str.substitute)(textTpl, s);
      s.$value = (0, _str.substitute)(valueTpl, s);
      s.$key = s.id ? s.id : hashcode(s.$text + '-' + s.$value);
      return s;
    }
  });
  return arr;
}

function hashcode(obj) {
  var hash = 0,
      i = void 0,
      chr = void 0,
      len = void 0,
      str = void 0;

  var type = typeof obj === 'undefined' ? 'undefined' : _typeof(obj);
  switch (type) {
    case 'object':
      //let newObj = {};
      //forEach(obj, (v, k) => v && (typeof v === 'object' || 'function') ? v.toString() : v);
      str = JSON.stringify(obj);
      break;
    case 'string':
      str = obj;
      break;
    default:
      str = obj.toString();
      break;
  }

  if (str.length === 0) return hash;
  for (i = 0, len = str.length; i < len; i++) {
    chr = str.charCodeAt(i);
    hash = (hash << 5) - hash + chr;
    hash |= 0; // Convert to 32bit integer
  }
  return hash.toString(36);
}

function sortByKey(obj) {
  if (!obj) {
    return {};
  }

  var newObj = {};
  Object.keys(obj).sort().forEach(function (key) {
    newObj[key] = obj[key];
  });

  return newObj;
}

function shallowEqual(objA, objB) {
  if (objA === objB) {
    return true;
  }

  if ((typeof objA === 'undefined' ? 'undefined' : _typeof(objA)) !== 'object' || objA === null || (typeof objB === 'undefined' ? 'undefined' : _typeof(objB)) !== 'object' || objB === null) {
    return false;
  }

  var keysA = Object.keys(objA);

  if (keysA.length !== Object.keys(objB).length) {
    return false;
  }

  for (var i = 0, key; i < keysA.length; i++) {
    key = keysA[i];
    if (!objB.hasOwnProperty(key) || objA[key] !== objB[key]) {
      return false;
    }
  }

  return true;
}

function type(val) {
  switch (toString.call(val)) {
    case '[object Date]':
      return 'date';
    case '[object RegExp]':
      return 'regexp';
    case '[object Arguments]':
      return 'arguments';
    case '[object Array]':
      return 'array';
    case '[object Error]':
      return 'error';
  }

  if (val === null) {
    return 'null';
  }
  if (val === undefined) {
    return 'undefined';
  }
  if (val !== val) {
    return 'nan';
  }
  if (val && val.nodeType === 1) {
    return 'element';
  }

  val = val.valueOf ? val.valueOf() : Object.prototype.valueOf.apply(val);

  return typeof val === 'undefined' ? 'undefined' : _typeof(val);
}

function merge(target) {
  if (target === undefined || target === null) {
    return {};
  }

  var to = Object(target);
  for (var i = 1; i < arguments.length; i++) {
    var nextSource = arguments[i];
    if (nextSource === undefined || nextSource === null) {
      continue;
    }
    nextSource = Object(nextSource);

    var keysArray = Object.keys(nextSource);
    for (var nextIndex = 0, len = keysArray.length; nextIndex < len; nextIndex++) {
      var nextKey = keysArray[nextIndex];

      // Object.Keys can't get enumerable key
      //var desc = Object.getOwnPropertyDescriptor(nextSource, nextKey);
      //if (desc !== undefined && desc.enumerable) {
      to[nextKey] = nextSource[nextKey];
      //}
    }
  }
  return to;
}

function clone(obj) {
  switch (type(obj)) {
    case 'object':
      var copy = {};
      Object.keys(obj).forEach(function (key) {
        copy[key] = clone(obj[key]);
      });
      return copy;

    case 'element':
      return obj.cloneNode(true);

    case 'array':
      var arr = new Array(obj.length);
      for (var i = 0, l = obj.length; i < l; i++) {
        arr[i] = clone(obj[i]);
      }
      return arr;

    case 'regexp':
      // from millermedeiros/amd-utils - MIT
      var flags = '';
      flags += obj.multiline ? 'm' : '';
      flags += obj.global ? 'g' : '';
      flags += obj.ignoreCase ? 'i' : '';
      return new RegExp(obj.source, flags);

    case 'date':
      return new Date(obj.getTime());

    default:
      // string, number, boolean, …
      return obj;
  }
}

},{"./str":17}],10:[function(require,module,exports){
'use strict';

var _qwest = require('./qwest');

var _qwest2 = _interopRequireDefault(_qwest);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

module.exports = function ajax(mothed, url, data, options) {
  return _qwest2.default[mothed](url, data, options);
};

},{"./qwest":14}],11:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getCache = getCache;
exports.setCache = setCache;

var _pinkyswear = require('pinkyswear');

var _pinkyswear2 = _interopRequireDefault(_pinkyswear);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var STORAGE_KEY = '517abb684366799b';
var storage = window && window.localStorage ? window.localStorage : null;

var CACHE = {};

if (storage) {
  var item = storage.getItem(STORAGE_KEY);
  if (item) {
    try {
      CACHE = JSON.parse(item) || {};
      clean();
    } catch (e) {
      console.warn(e);
    }
  }
}

function getCache(key) {
  var data = CACHE[key];
  if (!data) {
    return null;
  }

  if (data.expire < new Date().getTime()) {
    setCache(key, null);
    return null;
  }

  var promise = (0, _pinkyswear2.default)(function (pinky) {
    pinky.send = function () {
      promise(true, [data.data]);
    };

    pinky.complete = function (f) {
      return pinky.then(f, f);
    };

    pinky['catch'] = function (f) {
      return pinky.then(null, f);
    };

    pinky.cancel = function () {};

    return pinky;
  });

  promise.send();

  return promise;
}

function setCache(key, data) {
  var expire = arguments.length <= 2 || arguments[2] === undefined ? 3600 : arguments[2];

  if (data === null) {
    delete CACHE[key];
  } else {
    expire *= 1000;
    CACHE[key] = {
      data: data,
      expire: new Date().getTime() + expire
    };
  }
  save();
}

// use single item handle expire
function save() {
  if (!storage) {
    return;
  }
  clean();
  storage.setItem(STORAGE_KEY, JSON.stringify(CACHE));
}

function clean() {
  var expire = new Date().getTime();
  Object.keys(CACHE).forEach(function (key) {
    if (expire > (CACHE[key].expire || 0)) {
      delete CACHE[key];
    }
  });
}

},{"pinkyswear":5}],12:[function(require,module,exports){
'use strict';

var _objectAssign = require('object-assign');

var _objectAssign2 = _interopRequireDefault(_objectAssign);

var _ajax = require('./ajax');

var _ajax2 = _interopRequireDefault(_ajax);

var _jsonp = require('./jsonp');

var _jsonp2 = _interopRequireDefault(_jsonp);

var _util = require('./util');

var _cache = require('./cache');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var peer = null;
var defaultData = {};
var defaultOptions = {};

function fetch(method, url) {
  var data = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];
  var options = arguments.length <= 3 || arguments[3] === undefined ? {} : arguments[3];

  options = (0, _objectAssign2.default)({}, defaultOptions, options);
  data = (0, _objectAssign2.default)({}, defaultData, data);
  var key = (0, _util.generateKey)(method, url, data);
  var cache = options.cache;
  var promise = void 0;
  if (cache > 0) {
    promise = (0, _cache.getCache)(key);
    if (promise !== null) {
      return promise;
    }
  }
  if (method === 'jsonp') {
    promise = (0, _jsonp2.default)(url, data, options);
  } else {
    promise = (0, _ajax2.default)(method, url, data, options);
  }

  if (typeof peer === 'function') {
    promise = peer(promise);
  }

  if (cache > 0) {
    promise.then(function (res) {
      if (!(res instanceof Error)) {
        (0, _cache.setCache)(key, res, cache);
      }
      return res;
    });
  }

  return promise;
}

function _fetch(method) {
  return function () {
    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return fetch.apply(undefined, [method].concat(args));
  };
}

function create() {
  var preset = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

  var _ = function _(method) {
    return function (url, data, options) {
      data = (0, _objectAssign2.default)({}, preset.data, data);
      options = (0, _objectAssign2.default)({}, preset.options, options);

      var promise = fetch(method, url, data, options);
      if (preset.promise) {
        promise = preset.promise(promise);
      }

      return promise;
    };
  };

  return ['get', 'post', 'put', 'delete', 'jsonp'].reduce(function (obj, k) {
    obj[k] = _(k);
    return obj;
  }, {});
}

module.exports = {
  get: _fetch('get'),

  post: _fetch('post'),

  put: _fetch('put'),

  'delete': _fetch('delete'),

  jsonp: _fetch('jsonp'),

  create: create,

  setPeer: function setPeer(fn) {
    console.warn('setPeer is deprecated, use create instead.');
    peer = fn;
    return this;
  },

  setDefaultData: function setDefaultData(obj) {
    console.warn('setDefaultData is deprecated, use create instead.');
    defaultData = (0, _objectAssign2.default)(defaultData, obj);
  },

  setDefaultOptions: function setDefaultOptions(obj) {
    console.warn('setDefaultOptions is deprecated, use create instead.');
    defaultOptions = (0, _objectAssign2.default)(defaultOptions, obj);
  }
};

},{"./ajax":10,"./cache":11,"./jsonp":13,"./util":15,"object-assign":4}],13:[function(require,module,exports){
'use strict';

var _pinkyswear = require('pinkyswear');

var _pinkyswear2 = _interopRequireDefault(_pinkyswear);

var _util = require('./util');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var count = 0;

module.exports = function (url, data) {
  var options = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

  var promise = (0, _pinkyswear2.default)(function (pinky) {
    var id = options.name || '__cb' + (new Date().getTime().toString() + count++).substr(-10);
    var timeout = typeof options.timeout === 'number' ? options.timeout : 60000;
    var script = void 0;
    var timer = void 0;

    function cleanup() {
      if (script.parentNode) {
        script.parentNode.removeChild(script);
      }
      window[id] = function () {};
      if (timer) {
        clearTimeout(timer);
      }
    }

    pinky.send = function () {
      if (timeout) {
        timer = setTimeout(function () {
          cleanup();
          promise(false, [new Error('timeout')]);
        }, timeout);
      }

      window[id] = function (res) {
        cleanup();
        promise(true, [res]);
      };

      // add qs component
      var callback = options.callback || 'callback';
      data = data || {};
      data[callback] = id;
      url = (0, _util.solveUrl)(url, data);

      // create script
      script = document.createElement('script');
      script.src = url;
      document.head.appendChild(script);
    };

    pinky['catch'] = function (f) {
      return pinky.then(null, f);
    };

    pinky['complete'] = function (f) {
      return pinky.then(f, f);
    };

    pinky.cancel = function () {
      if (window[id]) {
        cleanup();
      }
    };

    return pinky;
  });

  if (options.delay > 0) {
    setTimeout(function () {
      promise.send();
    }, options.delay);
  } else {
    promise.send();
  }

  return promise;
};

},{"./util":15,"pinkyswear":5}],14:[function(require,module,exports){
'use strict';

/*! qwest 2.2.6 (https://github.com/pyrsmk/qwest) */
// add delay option

module.exports = function () {

	var global = window || this,
	    pinkyswear = require('pinkyswear'),
	    jparam = require('jquery-param'),

	// Default response type for XDR in auto mode
	defaultXdrResponseType = 'json',

	// Default data type
	defaultDataType = 'post',

	// Variables for limit mechanism
	_limit = null,
	    requests = 0,
	    request_stack = [],

	// Get XMLHttpRequest object
	getXHR = function getXHR() {
		return global.XMLHttpRequest ? new global.XMLHttpRequest() : new global.ActiveXObject('Microsoft.XMLHTTP');
	},

	// Guess XHR version
	xhr2 = getXHR().responseType === '',


	// Core function
	qwest = function qwest(method, url, data, options, before) {

		// Format
		method = method.toUpperCase();
		data = data || null;
		options = options || {};

		// Define variables
		var nativeResponseParsing = false,
		    crossOrigin,
		    xhr,
		    xdr = false,

		//timeoutInterval,
		//aborted = false,
		attempts = 0,
		    headers = {},
		    mimeTypes = {
			text: '*/*',
			xml: 'text/xml',
			json: 'application/json',
			post: 'application/x-www-form-urlencoded'
		},
		    accept = {
			text: '*/*',
			xml: 'application/xml; q=1.0, text/xml; q=0.8, */*; q=0.1',
			json: 'application/json; q=1.0, text/*; q=0.8, */*; q=0.1'
		},
		    vars = '',

		//serialized,
		response,
		    sending = false,

		//delayed = false,
		timeout_start,


		// Create the promise
		promise = pinkyswear(function (pinky) {
			pinky['catch'] = function (f) {
				return pinky.then(null, f);
			};
			pinky.complete = function (f) {
				return pinky.then(f, f);
			};
			// Override
			if ('pinkyswear' in options) {
				for (var i in options.pinkyswear) {
					pinky[i] = options.pinkyswear[i];
				}
			}
			pinky.send = function () {
				// Prevent further send() calls
				if (sending) {
					return;
				}
				// Reached request limit, get out!
				if (requests == _limit) {
					request_stack.push(pinky);
					return;
				}
				++requests;
				sending = true;
				// Start the chrono
				timeout_start = new Date().getTime();
				// Get XHR object
				xhr = getXHR();
				if (crossOrigin) {
					if (!('withCredentials' in xhr) && global.XDomainRequest) {
						xhr = new XDomainRequest(); // CORS with IE8/9
						xdr = true;
						if (method != 'GET' && method != 'POST') {
							method = 'POST';
						}
					}
				}
				// Open connection
				if (xdr) {
					xhr.open(method, url);
				} else {
					xhr.open(method, url, options.async, options.user, options.password);
					if (xhr2 && options.async) {
						xhr.withCredentials = options.withCredentials;
					}
				}
				// Set headers
				if (!xdr) {
					for (var i in headers) {
						if (headers[i]) {
							xhr.setRequestHeader(i, headers[i]);
						}
					}
				}
				// Verify if the response type is supported by the current browser
				if (xhr2 && options.responseType != 'document' && options.responseType != 'auto') {
					// Don't verify for 'document' since we're using an internal routine
					try {
						xhr.responseType = options.responseType;
						nativeResponseParsing = xhr.responseType == options.responseType;
					} catch (e) {}
				}
				// Plug response handler
				if (xhr2 || xdr) {
					xhr.onload = handleResponse;
					xhr.onerror = handleError;
				} else {
					xhr.onreadystatechange = function () {
						if (xhr.readyState == 4) {
							handleResponse();
						}
					};
				}
				// Override mime type to ensure the response is well parsed
				if (options.responseType != 'auto' && 'overrideMimeType' in xhr) {
					xhr.overrideMimeType(mimeTypes[options.responseType]);
				}
				// Run 'before' callback
				if (before) {
					before(xhr);
				}
				// Send request
				if (xdr) {
					// http://cypressnorth.com/programming/internet-explorer-aborting-ajax-requests-fixed/
					xhr.onprogress = function () {};
					xhr.ontimeout = function () {};
					xhr.onerror = function () {};
					// https://developer.mozilla.org/en-US/docs/Web/API/XDomainRequest
					setTimeout(function () {
						xhr.send(method != 'GET' ? data : null);
					}, 0);
				} else {
					xhr.send(method != 'GET' ? data : null);
				}
			};
			return pinky;
		}),


		// Handle the response
		handleResponse = function handleResponse() {
			// Prepare
			var responseType;
			--requests;
			sending = false;
			// Verify timeout state
			// --- https://stackoverflow.com/questions/7287706/ie-9-javascript-error-c00c023f
			if (new Date().getTime() - timeout_start >= options.timeout) {
				if (!options.attempts || ++attempts != options.attempts) {
					promise.send();
				} else {
					promise(false, [new Error('Timeout (' + url + ')')], response, xhr);
				}
				return;
			}
			// Launch next stacked request
			if (request_stack.length) {
				request_stack.shift().send();
			}
			// Handle response
			try {
				// Process response
				if (nativeResponseParsing && 'response' in xhr && xhr.response !== null) {
					response = xhr.response;
				} else if (options.responseType == 'document') {
					var frame = document.createElement('iframe');
					frame.style.display = 'none';
					document.body.appendChild(frame);
					frame.contentDocument.open();
					frame.contentDocument.write(xhr.response);
					frame.contentDocument.close();
					response = frame.contentDocument;
					document.body.removeChild(frame);
				} else {
					// Guess response type
					responseType = options.responseType;
					if (responseType == 'auto') {
						if (xdr) {
							responseType = defaultXdrResponseType;
						} else {
							var ct = xhr.getResponseHeader('Content-Type') || '';
							if (ct.indexOf(mimeTypes.json) > -1) {
								responseType = 'json';
							} else if (ct.indexOf(mimeTypes.xml) > -1) {
								responseType = 'xml';
							} else {
								responseType = 'text';
							}
						}
					}
					// Handle response type
					switch (responseType) {
						case 'json':
							try {
								if ('JSON' in global) {
									response = JSON.parse(xhr.responseText);
								} else {
									response = eval('(' + xhr.responseText + ')');
								}
							} catch (e) {
								throw 'Error while parsing JSON body : ' + e;
							}
							break;
						case 'xml':
							// Based on jQuery's parseXML() function
							try {
								// Standard
								if (global.DOMParser) {
									response = new DOMParser().parseFromString(xhr.responseText, 'text/xml');
								}
								// IE<9
								else {
										response = new global.ActiveXObject('Microsoft.XMLDOM');
										response.async = 'false';
										response.loadXML(xhr.responseText);
									}
							} catch (e) {
								response = undefined;
							}
							if (!response || !response.documentElement || response.getElementsByTagName('parsererror').length) {
								throw 'Invalid XML';
							}
							break;
						default:
							response = xhr.responseText;
					}
				}
				// Late status code verification to allow passing data when, per example, a 409 is returned
				// --- https://stackoverflow.com/questions/10046972/msie-returns-status-code-of-1223-for-ajax-request
				if ('status' in xhr && !/^2|1223/.test(xhr.status)) {
					throw xhr.status + ' (' + xhr.statusText + ')';
				}
				// Fulfilled
				promise(true, [response, xhr]);
			} catch (e) {
				// Rejected
				if (typeof e === 'string') {
					e = new Error(e);
				}
				promise(false, [e, response, xhr]);
			}
		},


		// Handle errors
		handleError = function handleError() {
			--requests;
			promise(false, [new Error('Connection aborted'), null, xhr]);
		};

		// Normalize options
		options.async = 'async' in options ? !!options.async : true;
		options.cache = 'cache' in options ? !!options.cache : false;
		options.dataType = 'dataType' in options ? options.dataType.toLowerCase() : defaultDataType;
		options.responseType = 'responseType' in options ? options.responseType.toLowerCase() : 'auto';
		options.user = options.user || '';
		options.password = options.password || '';
		options.withCredentials = !!options.withCredentials;
		options.timeout = 'timeout' in options ? parseInt(options.timeout, 10) : 30000;
		options.attempts = 'attempts' in options ? parseInt(options.attempts, 10) : 1;

		// Guess if we're dealing with a cross-origin request
		i = url.match(/\/\/(.+?)\//);
		crossOrigin = i && (i[1] ? i[1] != location.host : false);

		// Prepare data
		if ('ArrayBuffer' in global && data instanceof ArrayBuffer) {
			options.dataType = 'arraybuffer';
		} else if ('Blob' in global && data instanceof Blob) {
			options.dataType = 'blob';
		} else if ('Document' in global && data instanceof Document) {
			options.dataType = 'document';
		} else if ('FormData' in global && data instanceof FormData) {
			options.dataType = 'formdata';
		}
		switch (options.dataType) {
			case 'json':
				data = JSON.stringify(data);
				break;
			case 'post':
				data = jparam(data);
		}

		// Prepare headers
		if (options.headers) {
			var format = function format(match, p1, p2) {
				return p1 + p2.toUpperCase();
			};
			for (var i in options.headers) {
				headers[i.replace(/(^|-)([^-])/g, format)] = options.headers[i];
			}
		}
		if (!('Content-Type' in headers) && method != 'GET') {
			if (options.dataType in mimeTypes) {
				if (mimeTypes[options.dataType]) {
					headers['Content-Type'] = mimeTypes[options.dataType];
				}
			}
		}
		if (!headers.Accept) {
			headers.Accept = options.responseType in accept ? accept[options.responseType] : '*/*';
		}
		if (!crossOrigin && !('X-Requested-With' in headers)) {
			// (that header breaks in legacy browsers with CORS)
			headers['X-Requested-With'] = 'XMLHttpRequest';
		}
		if (!crossOrigin && !options.cache && !('Cache-Control' in headers)) {
			headers['Cache-Control'] = 'no-cache';
		}

		// Prepare URL
		if (method == 'GET' && data) {
			vars += data;
		}
		if (vars) {
			url += (/\?/.test(url) ? '&' : '?') + vars;
		}

		// Start the request
		if (options.async) {
			if (options.delay > 0) {
				setTimeout(function () {
					promise.send();
				}, options.delay);
			} else {
				promise.send();
			}
		}

		// Return promise
		return promise;
	};

	// Return the external qwest object
	return {
		base: '',
		get: function get(url, data, options, before) {
			return qwest('GET', this.base + url, data, options, before);
		},
		post: function post(url, data, options, before) {
			return qwest('POST', this.base + url, data, options, before);
		},
		put: function put(url, data, options, before) {
			return qwest('PUT', this.base + url, data, options, before);
		},
		'delete': function _delete(url, data, options, before) {
			return qwest('DELETE', this.base + url, data, options, before);
		},
		map: function map(type, url, data, options, before) {
			return qwest(type.toUpperCase(), this.base + url, data, options, before);
		},
		xhr2: xhr2,
		limit: function limit(by) {
			_limit = by;
		},
		setDefaultXdrResponseType: function setDefaultXdrResponseType(type) {
			defaultXdrResponseType = type.toLowerCase();
		},
		setDefaultDataType: function setDefaultDataType(type) {
			defaultDataType = type.toLowerCase();
		}
	};
}();

},{"jquery-param":3,"pinkyswear":5}],15:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.solveUrl = solveUrl;
exports.generateKey = generateKey;

var _blueimpMd = require('blueimp-md5');

var _blueimpMd2 = _interopRequireDefault(_blueimpMd);

var _jqueryParam = require('jquery-param');

var _jqueryParam2 = _interopRequireDefault(_jqueryParam);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function solveUrl(url, data) {
  var queryString = (0, _jqueryParam2.default)(data);
  return url + (url.indexOf('?') >= 0 ? '&' : '?') + queryString;
}

function generateKey(method, url, data) {
  data = data || {};

  // sort by key
  var sorted = Object.keys(data).sort().map(function (key) {
    return key + '=' + data[key];
  });
  sorted = sorted.join('&');
  var key = method + ':' + url + ':' + sorted;

  // short key length
  if (key.length > 32) {
    key = (0, _blueimpMd2.default)(key);
  }
  return key;
}

},{"blueimp-md5":1,"jquery-param":3}],16:[function(require,module,exports){
'use strict';

module.exports = {
  'email': /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(\.[a-z0-9-]+)*$/i,
  'url': /^(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$/,
  'number': /^\s*(\-|\+)?(\d+|(\d*(\.\d*)))*\s*$/,
  //'date': /^(\d{4})-(\d{2})-(\d{2})$/,
  'alpha': /^[a-z ._-]+$/i,
  'alphanum': /^[a-z0-9_]+$/i,
  'password': /^[\x00-\xff]+$/,
  'integer': /^[-+]?[0-9]*$/,
  'tel': /^[\d\s ().-]+$/,
  'hex': /^#[0-9a-f]{6}?$/i,
  'rgb': new RegExp('^rgb\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*\\)$'),
  'rgba': new RegExp('^rgba\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*((0.[1-9]*)|[01])\\s*\\)$'),
  'hsv': new RegExp('^hsv\\(\\s*(0|[1-9]\\d?|[12]\\d\\d|3[0-5]\\d)\\s*,\\s*((0|[1-9]\\d?|100)%)\\s*,\\s*((0|[1-9]\\d?|100)%)\\s*\\)$')
};

},{}],17:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.nextUid = nextUid;
exports.format = format;
exports.substitute = substitute;
exports.toArray = toArray;
exports.toStyleObject = toStyleObject;
var uid = Date.now();
function nextUid() {
  return (uid++).toString(36);
}

function format() {
  var args = [].slice.call(arguments),
      str = args.shift();
  return str.replace(/{(\d+)}/g, function (match, number) {
    return args[number] !== undefined ? args[number] : match;
  });
}

function substitute(str, obj) {
  if (typeof str === 'string') {
    return str.replace(/\\?\{([^{}]+)\}/g, function (match, name) {
      if (match.charAt(0) === '\\') {
        return match.slice(1);
      }
      return obj[name] === null || obj[name] === undefined ? '' : obj[name];
    });
  } else if (typeof str === 'function') {
    return str(obj);
  }
}

function toArray(value, sep) {
  if (value === null || value === undefined) {
    value = [];
  }
  if (typeof value === 'string' && sep) {
    value = value.split(sep);
  } else if (!(value instanceof Array)) {
    value = [value.toString()];
  } else if (sep) {
    // if use sep, convert every value to string
    value = value.map(function (v) {
      return v.toString();
    });
  }

  return value;
}

function toStyleObject(str) {
  if (!str) {
    return undefined;
  }

  var style = {};
  var kv = void 0;
  str.split(';').forEach(function (s) {
    s = s.trim();
    if (!s) {
      return;
    }

    kv = s.split(':');
    if (kv.length < 2) {
      console.warn('style is error');
      return;
    }
    var key = kv[0].replace(/-./g, function (r) {
      return r.replace('-', '').toUpperCase();
    }).trim();
    style[key] = kv[1].trim();
  });

  return style;
}

},{}]},{},[8]);
