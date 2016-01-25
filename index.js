var self = require("sdk/self");
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
let { Cu, Cc, Ci } = require('chrome');
var menuItem = require("menuitem");
var hoba =require("./lib/hoba.js"); // HOBA specific libs
Cu.importGlobalProperties(["crypto"]); // Bring in our crypto libraries

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

  var origin = hoba.get_origin(aSubject.URI.spec)
  if(! getKey(origin, realm)){
    dump("\nNo key")
    // Make new key
  }else{
    dump("\nKey present")
    // Do a post to some URI
  }

  //  dump("\ncookie:" + req.getResponseHeader("Set-Cookie"));

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
  if(! ss.storage.exists){
    ss.storage.exists = true;
    ss.storage.keys = {};
    return false;
  }else{
    return true;
  }
}

// Clobbers key storage
function resetKeyStorage(){
  ss.storage.keys = null
}

// Returns key associated with origin
// If no key stored returns false
function getKey(origin, realm){
  var idx = origin + "_" + realm;
  if(ss.storage.keys[idx] === undefined || ss.storage.keys[idx] === null){ 
    return false;
  }else{
    return ss.storage.keys[idx];
  }
}

// Stores a key
function storeKey(key, origin, realm=""){
  var idx = origin + "_" + realm;
  ss.storage.keys[idx] = key;
}

// Many thanks to https://github.com/diafygi/webcrypto-examples
function genKey(){
  crypto.subtle.generateKey( // See RFC 7486 section 7 for details
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x001, 0x00, 0x01]),
    hash: {name: "SHA-256"}    
  },
    true,
    ["sign", "verify"]
  )
    .then(function(key){ // Returns a keypair object
      return key;
    })
    .catch(function(err){
      dump("\ngenKey() Error:" + err);
    });
}
 
/*
  BEGIN EXECUTION
*/
dump("\nBEGIN EXECUTION");
ss.storage.derp = "DERP";
ss.storage.arr = [{id: "arr"}];
registerHttp(); // register http request listener
if(! initKeyStorage()){ // Initialize our storage
  dump("\nGenerating new RSA key and storing it");
  storeKey(genKey(), "tmp"); // Generate a new temporary RSA key pair
  dump("\nStored new RSA key");
}


