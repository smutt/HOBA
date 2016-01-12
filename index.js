var self = require('sdk/self');
var data = require("sdk/self").data;
var ss = require("sdk/simple-storage");
var menuItem = require("menuitem");
let { Cc, Ci } = require('chrome');

// HOBA specific libs
var hoba =require("./lib/hoba.js");

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
  
  // Is the connection using TLS?
  if(! aSubject.securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus) { return; }
  dump("\nhandleHttpReq: " + aSubject.URI.spec + " " + aSubject.contentType);

  var origin = hoba.get_origin(aSubject.URI.spec)
  dump("\norigin:" + origin)

  var authChal = hoba.make_auth_header_chal(chal)
  dump("\nauthChal:" + authChal)

  
  hoba.get_key
  
  //  dump("\ncookie:" + req.getResponseHeader("Set-Cookie"));

}

ss.storage.myString = "derp";

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

// register http request listener
registerHttp();
//unregisterHttp();


/*
// a dummy function, to show how tests work.
// to see how to test this function, look at test/test-index.js
function dummy(text, callback) {
  callback(text);
}

exports.dummy = dummy;
*/
