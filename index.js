// Some discussion and bitching by me, also some really helpful links from people
// https://discourse.mozilla-community.org/t/how-do-i-know-if-a-node-js-library-will-work-in-my-add-on/6845/8
// Info on JS SPKI to PEM conversion
// http://blog.engelke.com/2015/03/03/creating-x-509-certificates-with-web-crypto-and-pkijs/

var self = require("sdk/self");
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
let { Cu, Cc, Ci } = require('chrome');
var menuItem = require("menuitem");
var sha256 = require("lib/sha256.js");
Cu.importGlobalProperties(["crypto", "atob", "btoa", "XMLHttpRequest", "TextDecoder", "TextEncoder"]);

// Some global variables
var keys = {}; // Our dict of keys read into memory
var regInWork = false; // Are we in the process of registering?
var alg = "1"; // Not sure what should be here :(
var did = "firefox_hoba"; // Our arbitrary device ID

// Register observer service
function registerHttp(){
  var observerService =
    Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
  observerService.addObserver(handleHttpReq, "http-on-examine-response", false);
}

// Unregister observer service
function unregisterHttp(){
  var observerService =
    Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
  observerService.removeObserver(handleHttpReq, "http-on-examine-response");
}

// Handle HTTP listener events
function handleHttpReq(aSubject, aTopic, aData){
  // Mozilla says this is best practice
  if(aTopic != "http-on-examine-response") { return; }

  aSubject.QueryInterface(Ci.nsIHttpChannel);

  // Is the connection using TLS?
  if(! aSubject.securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus) { return; }
  //dump("\nhandleHttpReq: " + aSubject.URI.spec + " " + aSubject.contentType);

  // Is there auth, and is it HOBA?
  // For now we don't worry about challenge timeout
  // getResponseHeader() will bork if requesting non-present header
  try{
    var authChallenge = aSubject.getResponseHeader("WWW-Authenticate");
  }catch(err){
    return;
  }
  if(authChallenge.search(/(H|h)(O|o)(B|b)(A|a)/) == -1){ return; }
  var chalB64 = authChallenge.match(/challenge=(.*?),/)[1];

  // Are we finishing up an earlier registration?
  try{
    var hobaReg = aSubject.getResponseHeader("Hobareg");
  }catch(err){
    var hobaReg = null;
  }
  if(hobaReg !== null){
    if(hobaReg == "regok" && regInWork === true){
      dump("\nCompleting earlier registration");
      dump("\nHobareg:" + hobaReg);
      regInWork = false;
      rotatenextKey(keys['reginwork']['origin'], keys['reginwork']['realm']);
      keys['reginwork'] = {};
    }
  }
  
  if(authChallenge.search("realm=") == -1){
    var realm = "";
  }else{
    var realm = authChallenge.match(/realm=(.*?),/)[1];
  }
  dump("\nrealm:" + realm);
  
  var origin = getOrigin(aSubject.URI.spec); // Consider using aSubject.origin
  var tbsOrigin = getTbsOrigin(aSubject.URI.spec);
  getKey('pri', origin, realm)
    .then(function(privateKey){

      // Generate our 32-bit nonce
      var rands = new Uint32Array(1);
      crypto.getRandomValues(rands);
      var nonce = rands[0].toString(10);

      if(privateKey === false){ // We have no key for this origin/realm, begin registration
	dump("\nInitiating new registration for origin:" + origin + " realm:");
	regInWork = true;    
	crypto.subtle.exportKey("jwk", keys['next']['pub'])
	  .then(function(jwkObj){
	    jwk = JSON.stringify(jwkObj);
	    var kid = sha256.hash(jwk);
	    
	    var req = new XMLHttpRequest();
	    dump("\nRegister-URI:" + tbsOrigin + "/.well-known/hoba/register");
	    req.open("POST", tbsOrigin + "/.well-known/hoba/register", true);
	    req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	    req.onreadystatechange = function (){ // We currently don't deal with failures at all
	      if(req.readyState !== XMLHttpRequest.DONE){ return; }
	      dump("\nRegistration finished");

	      var hobaReg = req.getAllResponseHeaders().match(/hobareg:(.*)/i)[1].trim();
	      if(hobaReg == 'regok'){ // Registration succeeded
		dump("\nregok");
		regInWork = false;
		rotateNextKey(origin, realm);
	      }else if(hobaReg == 'reginwork'){ // HTTP POST returned but registration not done yet
		keys['reginwork'] = {}; // If there was a previous registration that never finished clobber it
		keys['reginwork']['pub'] = keys['next']['pub'];
		keys['reginwork']['pri'] = keys['next']['pri'];
		keys['reginwork']['origin'] = origin;
		keys['reginwork']['realm'] = realm;
	      }
	    };

	    genSignedTbsBlob(keys['next']['pri'], nonce, alg, tbsOrigin, realm, kid, chalB64)
	      .then(function(tbsSig){
		var tbsSigB64 = b64ToUrlb64(bufferToBase64(tbsSig));
		var kidB64 = b64ToUrlb64(btoa(kid));
		var nonceB64 = b64ToUrlb64(btoa(nonce));
		var authHeader = kidB64 + "." + chalB64 + "." + nonceB64 + "." + tbsSigB64;

		//dump("\nkid:" + kid + "\nchalB64:" + chalB64 + "\nnonce:" + nonce);
		//dump("\nauthHeader:" + authHeader);
		req.setRequestHeader("Authorization","HOBA result=" + authHeader);

		// RFC 7486 lists kid as optional but it's really not
		// It doesn't list alg but it's needed
		var postData = "pub=" + b64ToUrlb64(btoa(jwk));
		postData += "&kidtype=2&kid=" + kidB64; // We always use kidtype==2
		postData += "&didtype=0&did=" + did;
		postData += "&alg=" + alg;
		//dump("\npostData:" + postData);
		req.send(postData);
	      })
	      .catch(function(err){
		dump("\nError generating TBS signature for " + origin + " " + err);
	      });
	  })
	  .catch(function(err){
	    dump("\nError generating registration JWK for " + origin + " " + realm + " " + err);
	  });
      }else{ // We have a key for this origin, begin login
	dump("\nInitiating login for origin:" + origin + " realm:");
	getKey('pub', origin, realm)
	  .then(function(publicKey){
	    crypto.subtle.exportKey("jwk", publicKey)
	      .then(function(jwkObj){
		jwk = JSON.stringify(jwkObj);
		var kid = sha256.hash(jwk);
		dump("\nkid:" + kid);

		var req = new XMLHttpRequest();
		dump("\nLogin-URI:" + tbsOrigin + "/.well-known/hoba/login");
		req.open("GET", tbsOrigin + "/.well-known/hoba/login", true);

		genSignedTbsBlob(privateKey, nonce, alg, tbsOrigin, realm, kid, chalB64)
		  .then(function(tbsSig){
                    var tbsSigB64 = b64ToUrlb64(bufferToBase64(tbsSig));
                    var kidB64 = b64ToUrlb64(btoa(kid));
                    var nonceB64 = b64ToUrlb64(btoa(nonce));
                    var authHeader = kidB64 + "." + chalB64 + "." + nonceB64 + "." + tbsSigB64;

		    dump("\nkid:" + kid + "\nchalB64:" + chalB64 + "\nnonce:" + nonce);
                    dump("\nauthHeader:" + authHeader);
		    req.setRequestHeader("Authorization","HOBA result=" + authHeader);
		    req.send();
		  })
		  .catch(function(err){
		    dump("\nError generating TBS signature for " + origin + " " + err);
		  });
	      })
	      .catch(function(err){
		dump("\nError generating registration JWK for " + origin + " " + realm + " " + err);
	      });
	  })
	  .catch(function(err){
	    dump("\nError getting publicKey for " + origin + " " + err);
	  });
      }
    })
    .catch(function(err){
      dump("\nError getting privateKey for " + origin + " " + err);
    });
}

// Takes a privateKey obj, nonce, an HTTP Auth challenge, key-id, algorithm-id, http-origin and realm
// Returns Promise that returns signature of HOBA TBS-blob
function genSignedTbsBlob(privKey, nonce, alg, origin, realm, kid, chalB64){
  var tbsStr = genBlobField(b64ToUrlb64(btoa(nonce)));
  tbsStr += genBlobField(alg);
  tbsStr += genBlobField(origin);
  if(realm.length == 0){
    tbsStr += genBlobField("");
  }else{
    tbsStr += genBlobField(realm);
  }
  tbsStr += genBlobField(b64ToUrlb64(btoa(kid)));
  tbsStr += genBlobField(chalB64);
  //dump("\ntbsStr:" + tbsStr);

  var encoder = new TextEncoder("unicode-1-1-utf-8");
  return crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5'}, privKey, encoder.encode(tbsStr));
}

function genBlobField(str){
  return str.length + ":" + str;
}

// Takes a base64 encoded string
// Returns a base64url encoded string
function b64ToUrlb64(str){
  var rv = "";
  for(ii = 0; ii < str.length; ++ii){
    if (str[ii] == '+'){
	rv += '-';
    }else if(str[ii] == '/'){
      rv += '_';
    } else {
      rv += str[ii];
    }
  }
  return rv;
}

// From http://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
function bufferToBase64(buffer){
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var ii = 0; ii < len; ii++) {
    binary += String.fromCharCode(bytes[ii]);
  }
  return btoa(binary);
}

// Takes a URL
// Returns web origin as scheme:auth:port without slashes
function getOrigin(uri){
  return getTbsOrigin(uri).replace("://", ":");
}

// Takes a URL
// Returns web origin as scheme://auth:port with slashes
function getTbsOrigin(uri){
  var proto = uri.split("://")[0];
  var right = uri.split("://")[1];
  
  if(right.indexOf(":") == -1){
    if(proto == "http"){
      var port = ":80";
    }else if(proto == "https"){
      var port = ":443";
    }else{
      var port = ":80";
    }
    var host = right.split("/")[0];
  }else{
    var host = right.split(":")[0];
    var port = ":" + right.split(":")[1].split("/")[0];
  }
  return proto + "://" + host + port;
}

var menuItem = menuItem.Menuitem({
  id: "clickme",
  menuid: "menu_ToolsPopup",
  label: "HOBA",
  onCommand: function() {
    //    console.log("clicked");
    showCfgPanel()
  },
  insertbefore: "menu_pageInfo"
});

// Construct a panel, loading its content from the "cfgPanel.html"
// file in the "data" directory, and loading the "get-text.js" script
// into it.
// https://developer.mozilla.org/en-US/Add-ons/SDK/Tutorials/Display_a_Popup
var cfgPanel = require("sdk/panel").Panel({
  contentURL: data.url("cfgPanel.html"),
});

// Show the panel when the user activates the menu item
function showCfgPanel(state) {
  cfgPanel.show();
}

// Check if simple storage is already init'd
// If not init from scratch
// Return False if not init'd
// Otherwise return True
// For now this does not persist across restarts
function initKeyStorage(){
  if(! ss.storage.keys_exists || ss.storage.keys_exists === null || ss.storage.keys_exists == undefined){
    resetKeyStorage();
    ss.storage.keys_exists = true;
    ss.storage.keys = {};
    return false;
  }else{
    return true;
  }
}

// Resets V and NV key storage
function resetKeyStorage(){
  keys = {}
  ss.storage.keys = null
  ss.storage.keys_exists = false;
}
  
// Computes key Index for local non-volatile(NV) storage, simple-storage
// Takes a postFix, origin and realm
// postFix is usually "pub" or "pri"
function nvIdx(postFix, origin, realm=""){
  var delim = "!"; // Our delimeter for NV storage, it's not clear what the character space is for HTTP realms
  var origin = origin.replace(":", "_"); // Would rather not use colons in indexes
  return origin + delim + realm + delim + postFix;
}

// Computes key Index for volatile storage, the keys dict
// Takes an origin and realm
function vIdx(origin, realm=""){
  var delim = "!"; // Our delimeter for volatile storage, it's not clear what the character space is for HTTP realms
  var origin = origin.replace(":", "_"); // Would rather not use colons in keys
  return origin + delim + realm;
}

// Deletes a key from NV and V storage
function delKey(postFix, origin, realm=""){
  ss.storage.keys[nvIdx(postFix, origin, realm)] = null;
  keys[vIdx(origin, realm)] = null;
}

// Adds a string key to NV storage
function addKey(str, postFix, origin, realm=""){
  ss.storage.keys[nvIdx(postFix, origin, realm)] = str;
}

// Returns Promise to return a key associated with origin 
// If no key stored returns a Promise that resolves to false
function getKey(postFix, origin, realm=""){
  dump("\nEntered getKey postFix:" + postFix + " origin:" + origin + " realm:" + realm);
  var idx = nvIdx(postFix, origin, realm);
  if(ss.storage.keys[idx] === undefined || ss.storage.keys[idx] === null){
    dump("\nDid NOT find key for:" + idx);
    return Promise.resolve(false);
  }

  // Check volatile storage before hitting non-volatile
  var vidx = vIdx(origin, realm);
  if(keys[vidx] != undefined && keys[vidx] != null){
    if(keys[vidx][postFix] != undefined && keys[vidx][postFix] != null){
      if(keys[vidx][postFix] instanceof crypto.CryptoKey){
	return Promise.resolve(keys[vidx][postFix]);
      }
    }
  }
  
  if(postFix == "pub"){
    usage = "verify";
  }else{
    usage = "sign";
  }
  
  return crypto.subtle.importKey("jwk",
				 ss.storage.keys[idx],
				 { name: "RSASSA-PKCS1-v1_5",
				   hash: {name: "SHA-256"} },
				 true,
				 [usage]
				);
}

// Rotates next-key to an origin and realm, then regens next-key
// Takes an origin and realm, returns nothing
// Pauses https listening until next-key is refreshed
// Returns prior to execution finishing
function rotateNextKey(origin, realm){
  Promise.all([ // Export pub and pri to non-volatile local storage
    crypto.subtle.exportKey("jwk", keys['next']['pub'])
      .then(function(str){
	addKey(str, "pub", origin, realm);
      })
      .catch(function(err){
	dump("\nError storing public key for " + origin + " " + realm + " " + err)
      }),
    crypto.subtle.exportKey("jwk", keys['next']['pri'])
      .then(function(str){
	addKey(str, "pri", origin, realm);
      })
      .catch(function(err){
	dump("\nError storing private key " + origin + " " + realm + " " + err)
      })])
    .then(function(){
      unregisterHttp(); // Until we have a key ready we should not accept more HOBA attempts
      genNextKey()
	.then(function(keyPair){
	  dump("\nFinished generating new key-pair");
	  keys['next'] = {}; // Set our volatile copy of next-key
	  keys['next']['pub'] = keyPair.publicKey;
	  keys['next']['pri'] = keyPair.privateKey;
	  Promise.all([ // Export pub and pri to non-volatile local storage
	    crypto.subtle.exportKey("jwk", keys['next']['pub'])
	      .then(function(str){
		addKey(str, "pub", "next");
	      })
	      .catch(function(err){
		dump("\nError storing next public key" + " " + err)
	      }),
	    crypto.subtle.exportKey("jwk", keys['next']['pri'])
	      .then(function(str){
		addKey(str, "pri", "next");
	      })
	      .catch(function(err){
		dump("\nError storing next private key" + " " + err)
	      })])
	    .then(function(){
	      dump("\nFinished storing new key-pair");
	      registerHttp(); // register http request listener
	    })
	    .catch(function(err){
	      dump("\nError storing next keypair:" + err);
	    });
	})
	.catch(function(err){
	  dump("\nError generating next key after reg" + err);
	});
    })
    .catch(function(err){
      dump("\nError storing keypair for" + origin + " " + err);
    });
}

// Returns Promise to generate a key
// Many thanks to https://github.com/diafygi/webcrypto-examples
function genNextKey(){
  dump("\nEntered genNextkey");
  delKey("pub", "next");
  delKey("pri", "next");

  return crypto.subtle.generateKey( // See RFC 7486 section 7 for details
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x001, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  },
    true,
    ["sign", "verify"]
  );
}

/*
  BEGIN EXECUTION
*/
dump("\nBEGIN EXECUTION");

//resetKeyStorage();
if(! initKeyStorage()){ // Initialize our keys and storage
  dump("\nGenerating next RSA key and storing it");
  genNextKey()
    .then(function(keyPair){
      keys['next'] = {}; // Set our volatile copy of next-key
      keys['next']['pub'] = keyPair.publicKey;
      keys['next']['pri'] = keyPair.privateKey;

      Promise.all([ // Export pub and pri to non-volatile local storage
	crypto.subtle.exportKey("jwk", keys['next']['pub'])
	  .then(function(str){
	    addKey(str, "pub", "next");
	  })
	  .catch(function(err){
	    dump("\nError storing next public key" + " " + err)
	  }),
	crypto.subtle.exportKey("jwk", keys['next']['pri'])
	  .then(function(str){
	    addKey(str, "pri", "next");
	  })
	  .catch(function(err){
	    dump("\nError storing next private key" + " " + err)
	  })])
	.then(function(){
	  registerHttp(); // register http request listener
	})
	.catch(function(err){
	  dump("\nError storing next keypair:" + err);
	});
    })
    .catch(function(err){
      dump("\nError running genKey" + " " + err)
    });

}else{ // NV key storage exists, read next-key from NV to V storage
  keys['next'] = {};
  Promise.all([
    getKey("pub", "next")
      .then(function(key){ 
	keys['next']['pub'] = key;
      })
      .catch(function(err){
	dump("\nError importing next public key" + " " + err)
      }),
    getKey("pri", "next")
      .then(function(key){
	keys['next']['pri'] = key;
      })
      .catch(function(err){
	dump("\nError importing next private key" + " " + err)
      })])
    .then(function(){
      registerHttp(); // register http request listener
    })
    .catch(function(err){
      dump("\nError importing keys:" + err);
    });
}
