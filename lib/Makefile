#
# HOBA - No Password HTTP Authentication
#
# js Makefile
#
# Copyright (C) 2013, Tolerant Networks Limited
#
# Stephen Farrell, <stephen@tolerantnetworks.com>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

HOBA-MIN-INPUTS=jsrsasign/asn1hex-1.1.js jsrsasign/base64.js jsrsasign/crypto-1.0.js jsrsasign/jsbn2.js jsrsasign/jsbn.js jsrsasign/prng4.js jsrsasign/rng.js jsrsasign/rsa2.js jsrsasign/rsa.js jsrsasign/rsapem-1.1.js jsrsasign/rsasign-1.2.js jsrsasign/sha1.js jsrsasign/sha256.js miscjs/core-min.js miscjs/sha1.js miscjs/sha256.js binding.js hoba-gen-key.js hoba-ls.js hoba.js

WORKER-MIN-INPUTS=jsrsasign/jsbn.js jsrsasign/jsbn2.js jsrsasign/prng4.js jsrsasign/rng.js jsrsasign/rsa.js jsrsasign/rsa2.js jsrsasign/base64.js jsrsasign/sha1.js jsrsasign/sha256.js jsrsasign/rsapem-1.1.js jsrsasign/rsasign-1.2.js jsrsasign/base64.js jsrsasign/asn1hex-1.1.js jsrsasign/crypto-1.0.js miscjs/core-min.js miscjs/sha1.js miscjs/sha256.js hoba-gen-key.js worker.js

MINIFIER=yui-compressor

all: minnies/hoba-min.js minnies/worker-min.js minnies/binder-min.js

minnies/hoba-min.js:  $(HOBA-MIN-INPUTS)
	- cat $(HOBA-MIN-INPUTS) > minnies/hoba-min-inputs.js
	- $(MINIFIER) -o minnies/hoba-min.js minnies/hoba-min-inputs.js
	- rm -f minnies/hoba-min-inputs.js

minnies/worker-min.js: $(WORKER-MIN-INPUTS)
	- cat $(WORKER-MIN-INPUTS) > minnies/worker-min-inputs.js
	- $(MINIFIER) -o minnies/worker-min.js minnies/worker-min-inputs.js
	- rm -f minnies/worker-min-inputs.js

# this one can be fixed later - binder.js overloads hoba_register to
# auto-register, just need to change that name when ready
minnies/binder-min.js: binder.js
	- $(MINIFIER) -o minnies/binder-min.js binder.js

doxy: 
	../doc/jsdoc.sh

clean: 
	- rm -rf *.java jsbn/*.java
	- find . -name '*.java' -exec rm {} \;

