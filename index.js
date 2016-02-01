var self = require("sdk/self");
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
let { Cu, Cc, Ci } = require('chrome');
var menuItem = require("menuitem");
//var hoba = require("./lib/hoba.js"); // HOBA specific functions
var base64 = require("lib/jsbn/base64.js"); // Some string manipulation functions
Cu.importGlobalProperties(["crypto"]); // Bring in our crypto libraries

// Our dict of keys read into memory
// It's populated as needed from storage
var keys = {};
var regInProgress = false; // Are we in the process of registering?

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

  if(authChallenge.search("realm=") == -1){
    var realm = "";
  }else{
    var realm = authChallenge.match(/realm=(.*?),/)[1];
  }
  dump("\nrealm:" + realm);
  
  // Is the connection using TLS?
  if(! aSubject.securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus) { return; }
  dump("\nhandleHttpReq: " + aSubject.URI.spec + " " + aSubject.contentType);

  var origin = getOrigin(aSubject.URI.spec)
  privateKey = getKey(false, origin, realm);
  if(! privateKey){ // We have no key for this origin/realm
    dump("\nInitiating new registration for origin:" + origin + " realm:");
    regInProgress = true;
    crypto.subtle.exportKey("spki", keys['next']['pub'])
      .then(function(spki){
	dump("\nSPKI:" + spki);
	var pem = spkiToPem(spki);
	dump("\nPEM:" + pem);
	var req = new XMLHttpRequest();
	req.open("POST", origin + ".well-known/hoba/register", true);
	req.onreadystatechange = regCallback;
	req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

        var authres=hoba_make_auth_header();
        regreq.setRequestHeader("Authorization","HOBA "+authres);
        regreq.send(regparams);



      })
      .catch(function(err){
	dump("\nError generating registration SPKI for " + origin + " " + realm + " " + err);
      });
  }else{
    // Login

  }

  //  dump("\ncookie:" + req.getResponseHeader("Set-Cookie"));
  dump("\nEnd of handleHttpReq()");
}

// Callback function for the registration HTTP POST 
// Not yet written, code from Stephen
function regCallback(){
  if (regreq.readyState == 4 && regreq.status == 200) {                
    hobatext(regreq.responseText);
    privstruct.state="regok";
    privstruct.time=new Date();
    hoba_put_key(privstruct.origin,privstruct,privstruct.alg);
  } else if (regreq.readyState == 4 && regreq.status >= 400) {                
    privstruct.state="reginwork";
    privstruct.time=new Date();
    hoba_put_key(privstruct.origin,privstruct,privstruct.alg);
    hobatext(regreq.responseText);
  }
}

// Takes public key in SPKI format
// Returns PEM format
// Much of this was copied from Stephen Farrell's implementation
function spkiToPem(spki){
  var prefix = "-----BEGIN PUBLIC KEY-----%0D%0A";
  var postfix = "%0D%0A-----END PUBLIC KEY-----";
  var pem = add0D0As(urlb64(base64.hex2b64(spki)));
  return prefix + pem + postfix;
}

// Do some important conversion for spkiToPem
// Copied from Stephen Farrell's HOBA implementation
function urlb64(instr){
  var rv=""; 
  for(i = 0; i < instr.length; ++i){
    if(instr[i] == '+'){
      rv += '-';
    }else if(instr[i] == '/'){
      rv += '_';
    }else{
      rv += instr[i];
    }
  }
  return(rv);
}

// Add line breaks every 64 chars
// Copied from Stephen Farrell's HOBA implementation
function add0D0As(str){
  var rv = "";
  for (i=0; i != str.length; i++){
    rv += str[i];
    if(i && ((i%64) == 0)){
      rv += "%0D%0A";
    }
  }
  return rv;
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

