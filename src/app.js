var dns = require('dns');

dns.lookup('dnsseed.bluematt.me', {all:true},function (e, x) { console.log(e); console.log(x);});

