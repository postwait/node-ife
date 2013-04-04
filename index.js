var EventEmitter = require('events').EventEmitter;
var ife = require('./build/Release/IFEBinding').IFE;
ife.prototype.__proto__ = EventEmitter.prototype;
module.exports = ife; 
