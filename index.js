/*
  The file is part of the Firefox HOBA client.
  
  HOBA client is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  HOBA client is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.

  Copyright (C) 2016, Andrew McConachie, <andrew@depht.com>
*/

// Some discussion and bitching by me, also some really helpful links from people
// https://discourse.mozilla-community.org/t/how-do-i-know-if-a-node-js-library-will-work-in-my-add-on/6845/8
// Info on JS SPKI to PEM conversion
// http://blog.engelke.com/2015/03/03/creating-x-509-certificates-with-web-crypto-and-pkijs/

var self = require("sdk/self");
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
let {Cu, Cc, Ci} = require('chrome');
var menuItem = require("menuitem");
var sha256 = require("lib/sha256.js");
Cu.importGlobalProperties(["crypto", "atob", "btoa", "XMLHttpRequest", "TextDecoder", "TextEncoder"]);

// Some global variables. see RFC 7486 for details
var httpHandlerRegistered = false; // Is our HTTP handler function registered?
var dbg = true; // Set to true to enable debugging to the console
var keys = {}; // Our dict of keys read into memory
var regInWork = false; // Are we in the process of registering?
var alg = "0"; // We only support RSA-SHA256
var kidType = "0"; // We only support hashed public keys for kid-type
var didType = "0"; // This is the only entry in the IANA registry
var maxDidLength = 20; // Maximum character length for a device ID

// A simple wrapper for the dump() function
function hump(str){
  if(dbg){
    dump(str);
  }
}

// Adds a clickable to the "Tools" dropdown
var menuItem = menuItem.Menuitem({
  id: "clickme",
  menuid: "menu_ToolsPopup",
  label: "HOBA",
  onCommand: function(){
    showCfgPanel()
  },
  insertbefore: "menu_pageInfo"
});

// Construct a panel, loading its content from the "cfgPanel.html"
// file in the "data" directory, and loading the "get-text.js" script into it
// https://developer.mozilla.org/en-US/Add-ons/SDK/Tutorials/Display_a_Popup
var cfgPanel = require("sdk/panel").Panel({
  width:800,
  height:400,
  contentURL: data.url("cfgPanel.html"),
  contentScriptFile: data.url("cfgPanel.js"),
  contextMenu: true,
});

// When the panel is displayed it generated an event called
// "show": we will listen for that event and when it happens,
// send our own "show" event to the panel's script
// so the script can prepare the panel for display.
cfgPanel.on("show", function(){
  cfgPanel.port.emit("show", ss.storage.deviceID, ss.storage.usedKeys);
});

// Listen for messages called "finished" coming from the content script.
// If user set deviceID clobber storage and set new deviceID
cfgPanel.port.on("finished", function(deviceID){
  if(deviceID != null && deviceID.trim() != ""){    
    resetKeyStorage();
    initKeyStorage();
    ss.storage.deviceID = deviceID;
    genFirstNextKey();
  }
  cfgPanel.hide();
});

// Show the panel when the user activates the menu item
function showCfgPanel(state) {
  cfgPanel.show();
}

// Register observer service
function registerHttp(){
  if(! httpHandlerRegistered){
    httpHandlerRegistered = true;
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.addObserver(handleHttpReq, "http-on-examine-response", false);
  }
}

// Unregister observer service
function unregisterHttp(){
  if(httpHandlerRegistered){
    httpHandlerRegistered = false;
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.removeObserver(handleHttpReq, "http-on-examine-response");
  }
}

// Handle HTTP listener events
function handleHttpReq(aSubject, aTopic, aData){
  // Mozilla says this is best practice
  if(aTopic != "http-on-examine-response") { return; }

  aSubject.QueryInterface(Ci.nsIHttpChannel);

  // Is the connection using TLS?
  if(! aSubject.securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus) { return; }
  //hump("\nhandleHttpReq: " + aSubject.URI.spec + " " + aSubject.contentType);

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
  //hump("\nHandling HOBA HTTP Request");
  
  // Are we finishing up an earlier registration?
  try{
    var hobaReg = aSubject.getResponseHeader("Hobareg");
  }catch(err){
    var hobaReg = null;
  }
  if(hobaReg !== null){
    if(hobaReg == "regok" && regInWork === true){
      hump("\nCompleting earlier registration");
      hump("\nHobareg:" + hobaReg);
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
  
  var origin = getOrigin(aSubject.URI.spec); // Consider using aSubject.origin
  var tbsOrigin = getTbsOrigin(aSubject.URI.spec);
  getKey('pri', origin, realm)
    .then(function(privateKey){

      // Generate our 32-bit nonce
      var rands = new Uint32Array(1);
      crypto.getRandomValues(rands);
      var nonce = rands[0].toString(10);

      if(privateKey === false){ // We have no key for this origin/realm, begin registration
	hump("\nInitiating new registration for origin!" + origin + " realm!");
	regInWork = true;
	crypto.subtle.exportKey("jwk", keys['next']['pub'])
	  .then(function(jwkObj){
	    jwk = JSON.stringify(jwkObj);
	    var kid = sha256.hash(jwk).trim();
	    
	    var req = new XMLHttpRequest();
	    req.open("POST", tbsOrigin + "/.well-known/hoba/register", true);
	    req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	    req.onreadystatechange = function (){ // We currently don't deal with failures at all
	      if(req.readyState !== XMLHttpRequest.DONE){ return; }
	      hump("\nRegistration finished");

	      var hobaReg = req.getAllResponseHeaders().match(/hobareg:(.*)/i)[1].trim();
	      if(hobaReg == 'regok'){ // Registration succeeded
		hump("\nregok");
		if(regInWork == true){ // Defensive programming
		  regInWork = false;

		  // Set usedKeys info
		  var tmp = {};
		  tmp['kid'] = kid;
		  tmp['site'] = origin.split(":")[1];
		  tmp['realm'] = realm;
		  tmp['created'] = Date.now();
		  tmp['accessed'] = Date.now();
		  ss.storage.usedKeys.push(tmp);
		  
		  rotateNextKey(origin, realm);
		}
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

		//hump("\nkid:" + kid + "\nchalB64:" + chalB64 + "\nnonce:" + nonce);
		//hump("\nauthHeader:" + authHeader);
		req.setRequestHeader("Authorization","HOBA result=" + authHeader);

		// RFC 7486 lists kid as optional but it's really not
		// It doesn't list alg but it's also needed IMO
		var postData = "pub=" + b64ToUrlb64(btoa(jwk));
		postData += "&kidtype=" + kidType + "&kid=" + kidB64;
		postData += "&didtype=" + didType + "&did=" + ss.storage.deviceID;
		postData += "&alg=" + alg;
		//hump("\npostData:" + postData);
		req.send(postData);
	      })
	      .catch(function(err){
		hump("\nError generating TBS signature for " + origin + " " + err);
	      });
	  })
	  .catch(function(err){
	    hump("\nError generating registration JWK for " + origin + " " + realm + " " + err);
	  });
      }else{ // We have a key for this origin, begin login
	hump("\nInitiating login for origin!" + origin + " realm!");
	getKey('pub', origin, realm)
	  .then(function(publicKey){
	    crypto.subtle.exportKey("jwk", publicKey)
	      .then(function(jwkObj){
		jwk = JSON.stringify(jwkObj);
		var kid = sha256.hash(jwk);

		// Update the last accessed time for the key
		for(var ii = 0; ii<ss.storage.usedKeys.length; ii++){
		  if(ss.storage.usedKeys[ii]['kid'] === kid){
		    ss.storage.usedKeys[ii]['accessed'] = Date.now();
		  }
		}
		
		var req = new XMLHttpRequest();
		req.open("GET", tbsOrigin + "/.well-known/hoba/login", true);

		genSignedTbsBlob(privateKey, nonce, alg, tbsOrigin, realm, kid, chalB64)
		  .then(function(tbsSig){
                    var tbsSigB64 = b64ToUrlb64(bufferToBase64(tbsSig));
                    var kidB64 = b64ToUrlb64(btoa(kid));
                    var nonceB64 = b64ToUrlb64(btoa(nonce));
                    var authHeader = kidB64 + "." + chalB64 + "." + nonceB64 + "." + tbsSigB64;

		    //hump("\nkid:" + kid + "\nchalB64:" + chalB64 + "\nnonce:" + nonce);
                    //hump("\nauthHeader:" + authHeader);
		    req.setRequestHeader("Authorization","HOBA result=" + authHeader);
		    req.send();
		  })
		  .catch(function(err){
		    hump("\nError generating TBS signature for " + origin + " " + err);
		  });
	      })
	      .catch(function(err){
		hump("\nError generating registration JWK for " + origin + " " + realm + " " + err);
	      });
	  })
	  .catch(function(err){
	    hump("\nError getting publicKey for " + origin + " " + err);
	  });
      }
    })
    .catch(function(err){
      hump("\nError getting privateKey for " + origin + " " + err);
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
  //hump("\ntbsStr:" + tbsStr);

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

// Check if simple storage is already init'd
// If not init from scratch
// Return False if not init'd
// Otherwise return True
function initKeyStorage(){
  if(! ss.storage.keys_exists || ss.storage.keys_exists === null || ss.storage.keys_exists == undefined){
    resetKeyStorage();
    ss.storage.keys_exists = true;
    ss.storage.keys = {};

    // Generate a random deviceID
    var rands = new Uint16Array(1);
    crypto.getRandomValues(rands);
    ss.storage.deviceID = "firefox_" + rands[0].toString(10);

    // Init array for holding display information for keys used
    // Each entry has kid, site, realm, created, accessed
    // timestamps are JS timestamps in milliseconds since UNIX epoch
    ss.storage.usedKeys = [];

    return false;
  }else{
    return true;
  }
}

// Resets V and NV key storage
function resetKeyStorage(){
  keys = {}
  ss.storage.keys = null;
  ss.storage.deviceID = null;
  ss.storage.usedKeys = null;
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
  //hump("\nEntered getKey postFix!" + postFix + " origin!" + origin + " realm!" + realm);
  var idx = nvIdx(postFix, origin, realm);
  if(ss.storage.keys[idx] === undefined || ss.storage.keys[idx] === null){
    hump("\nDid NOT find key for:" + idx);
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
	hump("\nError storing public key for " + origin + " " + realm + " " + err)
      }),
    crypto.subtle.exportKey("jwk", keys['next']['pri'])
      .then(function(str){
	addKey(str, "pri", origin, realm);
      })
      .catch(function(err){
	hump("\nError storing private key " + origin + " " + realm + " " + err)
      })])
    .then(function(){
      unregisterHttp(); // Until we have a key ready we should not accept more HOBA attempts
      genNextKey()
	.then(function(keyPair){
	  hump("\nFinished generating new key-pair");
	  keys['next'] = {}; // Set our volatile copy of next-key
	  keys['next']['pub'] = keyPair.publicKey;
	  keys['next']['pri'] = keyPair.privateKey;
	  Promise.all([ // Export pub and pri to non-volatile local storage
	    crypto.subtle.exportKey("jwk", keys['next']['pub'])
	      .then(function(str){
		addKey(str, "pub", "next");
	      })
	      .catch(function(err){
		hump("\nError storing next public key" + " " + err)
	      }),
	    crypto.subtle.exportKey("jwk", keys['next']['pri'])
	      .then(function(str){
		addKey(str, "pri", "next");
	      })
	      .catch(function(err){
		hump("\nError storing next private key" + " " + err)
	      })])
	    .then(function(){
	      hump("\nFinished storing new key-pair");
	      registerHttp(); // register http request listener
	    })
	    .catch(function(err){
	      hump("\nError storing next keypair:" + err);
	    });
	})
	.catch(function(err){
	  hump("\nError generating next key after reg" + err);
	});
    })
    .catch(function(err){
      hump("\nError storing keypair for" + origin + " " + err);
    });
}

// Returns Promise to generate a key
// Many thanks to https://github.com/diafygi/webcrypto-examples
function genNextKey(){
  hump("\nEntered genNextkey");
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

// Generates our first next key if we have nothing in storage
// nextKey is actually the name of the key in storage, and this function generates it
// Takes nada, returns nada
function genFirstNextKey(){
  hump("\nGenerating first next RSA key and storing it");
  unregisterHttp();
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
	    hump("\nError storing next public key" + " " + err)
	  }),
	crypto.subtle.exportKey("jwk", keys['next']['pri'])
	  .then(function(str){
	    addKey(str, "pri", "next");
	  })
	  .catch(function(err){
	    hump("\nError storing next private key" + " " + err)
	  })])
	.then(function(){
	  registerHttp(); // register http request listener
	})
	.catch(function(err){
	  hump("\nError storing next keypair:" + err);
	});
    })
    .catch(function(err){
      hump("\nError running genKey" + " " + err)
    });
}

/*
  BEGIN EXECUTION
*/
hump("\nBEGIN EXECUTION");
//resetKeyStorage(); // This is only here for debugging

if(! initKeyStorage()){ // Initialize our keys and storage
  genFirstNextKey();
}else{ // NV key storage exists, read next-key from NV to V storage
  keys['next'] = {};
  Promise.all([
    getKey("pub", "next")
      .then(function(key){ 
	keys['next']['pub'] = key;
      })
      .catch(function(err){
	hump("\nError importing next public key" + " " + err)
      }),
    getKey("pri", "next")
      .then(function(key){
	keys['next']['pri'] = key;
      })
      .catch(function(err){
	hump("\nError importing next private key" + " " + err)
      })])
    .then(function(){
      registerHttp(); // register http request listener
    })
    .catch(function(err){
      hump("\nError importing keys:" + err);
    });
}
