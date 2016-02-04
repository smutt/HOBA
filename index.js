var self = require("sdk/self");
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
let { Cu, Cc, Ci } = require('chrome');
var menuItem = require("menuitem");
//var hoba = require("./lib/hoba.js"); // HOBA specific functions
//var base64 = require("lib/jsbn/base64.js"); // Some string manipulation functions
//var jwkToPem = require("jwk-to-pem");
Cu.importGlobalProperties(["crypto"]); // Bring in our crypto libraries
Cu.importGlobalProperties(["WindowBase64"]); // Bring in our base64 conversion functions

// Some global variables
var keys = {}; // Our dict of keys read into memory
var regInWork = false; // Are we in the process of registering?
var kid = "1"; // For now we just always use 1 for key-id
var alg = "1"; // Not sure what should be here :(

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

  // Is there auth, and is it HOBA?
  var authChallenge = aSubject.getResponseHeader("WWW-Authenticate");
  if(authChallenge.search(/(H|h)(O|o)(B|b)(A|a)/) == -1){ return; }
  var chal = authChallenge.match(/challenge=(.*?),/)[1]
  dump("\nchal:" + chal)

  // Are we finishing up an earlier registration
  var hobaReg = aSubject.getResponseHeader("Hobareg");
  if(authChallenge == "regok" && regInWork === true){
    regInWork = false;
    addKey(keys['reginwork']['pub'], true, keys['reginwork']['origin'], keys['reginwork']['realm']);
    addKey(keys['reginwork']['pri'], false, keys['reginwork']['origin'], keys['reginwork']['realm']);
    keys['reginwork'] = {};
  }
  
  if(authChallenge.search("realm=") == -1){
    var realm = "";
  }else{
    var realm = authChallenge.match(/realm=(.*?),/)[1];
  }
  dump("\nrealm:" + realm);
  
  // Is the connection using TLS?
  if(! aSubject.securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus) { return; }
  dump("\nhandleHttpReq: " + aSubject.URI.spec + " " + aSubject.contentType);

  var origin = getOrigin(aSubject.URI.spec);
  var tbsOrigin = getTbsOrigin(aSubject.URI.spec);
  privateKey = getKey(false, origin, realm);
  if(! privateKey){ // We have no key for this origin/realm, begin registration
    dump("\nInitiating new registration for origin:" + origin + " realm:");
    regInWork = true;
    crypto.subtle.exportKey("jwk", keys['next']['pub'])
      .then(function(jwk){
	var req = new XMLHttpRequest();
	req.open("POST", origin + ".well-known/hoba/register", true);
	req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	req.onreadystatechange = function (){ // We currently don't deal with failures
	  if(req.readyState !== XMLHttpRequest.DONE){ return; }
	  var hobaReg = aSubject.getResponseHeader("Hobareg");
	  if(hobaReg == "regok"){
	    regInWork = false;
	    addKey(keys['next']['pub'], true, origin, realm);
	    addKey(keys['next']['pri'], false, origin, realm);
	  }else{ // HTTP POST returned but registration not done yet
	    keys['reginwork'] = {};
	    keys['reginwork']['pub'] = keys['next']['pub'];
	    keys['reginwork']['pri'] = keys['next']['pri'];
	    keys['reginwork']['origin'] = origin;
	    keys['reginwork']['realm'] = realm;
	  }

	  unregisterHttp(); // Until we have a key ready we should not accept more HOBA attempts
	  genNextKey()
	    .then(function(){
	      registerHttp();
	    })
	    .catch(function(err){
	      dump("\nError generating new key after successful reg" + err);
	    });
	};

	var rands = new Uint32Array(1);
	crypto.getRandomValues(rands);
	var nonce = rands[0].toString();
	if(nonce.charAt(nonce.length-1) == "="){
          nonce = nonce.substring(0, nonce.length-1);
        }
	var tbsBlob = nonce.length().toString() + ":" + nonce;
	tbsBlob += alg.length().toString() + ":" + alg;
	tbsBlob += tbsOrigin.length().toString() + ":" + tbsOrigin;
	tbsBlob += realm.length().toString() + ":" + realm;
	tbsBlob += kid.length().toString() + ":" + kid;
	tbsBlob += chal.length().toString() + ":" + chal;
	crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5'}, keys['next']['pri'], tbsBlob)
	  .then(function(tbsOut){
	    var kid = b64ToUrlb64(WindowBase64.btoa(kid));
	    var nonce = b64ToUrlb64(WindowBase64.btoa(nonce));
	    var sig = b64ToUrlb64(WindowBase64.btoa(tbsOut));
	    var authHeader = kid + "." + chal + "." + nonce + "." + sig;
            req.setRequestHeader("Authorization","HOBA " + authHeader);
	    req.send(jwk); // For sure not right
	  })
	  .catch(function(err){
	    dump("\nError generating TBS signature for " + origin);
	  });
      })
      .catch(function(err){
	dump("\nError generating registration SPKI for " + origin + " " + realm + " " + err);
      });
  }else{ // We have a key for this origin, begin login


  }

  //  dump("\ncookie:" + req.getResponseHeader("Set-Cookie"));
  dump("\nEnd of handleHttpReq()");
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
  if(! ss.storage.keys_exists){
    resetKeyStorage();
    ss.storage.keys_exists = true;
    ss.storage.keys = {};
    return false;
  }else{
    return true;
  }
}

// Clobbers key storage
function resetKeyStorage(){
  ss.storage.keys = null
  ss.storage.keys_exists = false;
}

// Computes key Index for storage
function keyIdx(isPub, origin, realm=""){
  var delim = "!"; // Our delimeter for storage, it's not clear what the character space is for HTTP realms
  if(realm.length == 0){
    realm = " ";
  }
  if(isPub){
    return origin + delim + realm + delim + "pub";
  }else{
    return origin + delim + realm + delim + "pri";
  }
}

// Deletes a key from storage
function delKey(isPub, origin, realm=""){
  ss.storage.keys[keyIdx(isPub, origin, realm)] = null;
}

// Takes a string to 
// Adds a string key to local storage
function addKey(str, isPub, origin, realm=""){
  ss.storage.keys[keyIdx(isPub, origin, realm)] = str;
}

// Returns Promise to return a key associated with origin 
// from non-volatile storage
// If no key stored returns false
function getKey(isPub, origin, realm=""){
  dump("\nEntered getKey isPub:" + isPub + " origin:" + origin);
  var idx = keyIdx(isPub, origin, realm);
  if(ss.storage.keys[idx] === undefined || ss.storage.keys[idx] === null){
    return false;
  }

  if(isPub){
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
  
// Returns Promise to generate a key
// Many thanks to https://github.com/diafygi/webcrypto-examples
function genNextKey(){
  dump("\nEntered genNextkey");
  delKey(true, "next");
  delKey(false, "next");

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
      Promise.all([
	crypto.subtle.exportKey("jwk", keyPair.publicKey)
	  .then(function(str){
	    addKey(str, true, "next");
	    ss.storage.keys[keyIdx(true, "next")] = str;
	  })
	  .catch(function(err){
	    dump("\nError storing next public key")
	  }),
	crypto.subtle.exportKey("jwk", keyPair.privateKey)
	  .then(function(str){
	    addKey(str, false, "next");
	  })
	  .catch(function(err){
	    dump("\nError storing next private key")
	  })])
	.then(function(){
	  // Set our volatile copy of next-key
	  keys['next'] = {};
	  keys['next']['pub'] = keyPair.publicKey;
	  keys['next']['pri'] = keyPair.privateKey;
	  registerHttp(); // register http request listener
	})
	.catch(function(err){
	  dump("\nError storing next keypair:" + err);
	});
    })
    .catch(function(err){
      dump("\nError running genKey")
    });

}else{
  keys['next'] = {};
  Promise.all([
    getKey(true, "next")
      .then(function(key){ 
	keys['next']['pub'] = key;
      })
      .catch(function(err){
	dump("\nError importing next public key")
      }),
    getKey(false, "next")
      .then(function(key){
	keys['next']['pri'] = key;
      })
      .catch(function(err){
	dump("\nError importing next private key")
      })])
    .then(function(){
      registerHttp(); // register http request listener
    })
    .catch(function(err){
      dump("\nError importing keys:" + err);
    });
}

