/*!
 * @file worker.js
 * @brief Javascript computationally intensive bits: keygen & sign
 */
/* 
 * HOBA - No Password HTTP Authentication
 *
 * Copyright (C) 2013, Tolerant Networks Limited
 *
 * Stephen Farrell, <stephen@tolerantnetworks.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 */
// entry point from main (hoba.js)

self.addEventListener('message', function(e){
  importScripts('./hoba-gen-key.js');
  importScripts('./jsrsasign/jsbn.js');
  importScripts('./jsrsasign/jsbn2.js');
  importScripts('./jsrsasign/prng4.js');
  importScripts('./jsrsasign/rng.js');
  importScripts('./jsrsasign/rsa.js');
  importScripts('./jsrsasign/rsa2.js');
  importScripts('./jsrsasign/base64.js');
  importScripts('./jsrsasign/sha1.js');
  importScripts('./jsrsasign/sha256.js');
  importScripts('./jsrsasign/rsapem-1.1.js');
  importScripts('./jsrsasign/rsasign-1.2.js');
  importScripts('./jsrsasign/base64.js');
  importScripts('./jsrsasign/asn1hex-1.1.js');
  importScripts('./jsrsasign/crypto-1.0.js');
  importScripts('./miscjs/core-min.js');
  importScripts('./miscjs/sha1.js');
  importScripts('./miscjs/sha256.js');
  
  var data=e.data;
  var key2=null;
  var bgsigning=false;
  
  if (data.cmd=='gen') {
    if (key2==null) {
      //hobatext("worker starting to generate key");
      var key=hoba_gen_key(data.origin,data.alg);
      var pack= new Object; //={ 'iskey' : true, 'origin': origin, 'key': key, 'alg': alg}
      pack.iskey=true;
      pack.origin=data.origin;
      pack.key=key;
      pack.alg=data.alg;
      self.postMessage(pack);
      //key2=hoba_gen_key(data.origin,data.alg);
    } else {
      //hobatext("worker had a backup key ready:-)");
      var pack= new Object; //={ 'iskey' : true, 'origin': origin, 'key': key, 'alg': alg}
      pack.iskey=true;
      pack.origin=data.origin;
      pack.key=key2;
      pack.alg=data.alg;
      self.postMessage(pack);
      // and off we go again!
      //key2=hoba_gen_key(data.origin,data.alg);
    }
  } else if (data.cmd=='bgsign') {
    // sign once in background
    //hobatext("worker background signing");
    var res=make_auth_header_aux(data.alg,data.origin,data.tbsorigin,data.n,data.e,data.d,data.kid);
    var pack=new Object;
    pack.issig=true;
    pack.origin=data.origin;
    pack.alg=data.alg;
    pack.sig=res; 
    self.postMessage(pack);
  } else {
    self.postMessage({"mirror":e.data});
  }
}, false);

