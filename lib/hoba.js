/*!
 * @file hoba.js
 * @brief Javascript external i/f for HOBA
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

/*

/// globals
var regreq = new Object;
var unregreq = new Object;
var privstruct = new Object;
var authreq = new Object;
var worker = new Object;
var keygenfails=0;
var ismsie=false;
var workerok=false;
var bgsigning=true;
var cachedsig="";
var cachedsigtime=new Date(1970);
/// TODO make this part of the challenge (or derived from)
var maxchalwindow=200000; // in ms

function dscr() 
{
	// print a crlf and date string before some hobatext
	return "\n" + Date() + " ";
}

function replacer(where,what)
{
	var there=document.getElementById(where);
	var newnode=document.createElement();
	newnode.innerHTML=what;
	var oldnode=there.firstChild;
	var output=there.replaceChild(newnode,oldnode);
	return;
}

function mshobatext(str)
{
	var there=document.getElementById("hobatext");
	var oldstr=there.innerText;
	var newstr=dscr()+str+oldstr;
	there.innerText=newstr;
	return;
}

function hobatext(str) 
{
	// add more hobatext output
	if (ismsie) {
		mshobatext(str);
		return;
	}
	var ht=document.getElementById("hobatext");
	if (ht!=null) {
		ht.innerHTML =    dscr() + str + ht.innerHTML;
	}
	hoba_show_state();
	return
}

function clearhobatext(str) 
{
	// add more hobatext output
	var ht=document.getElementById("hobatext");
	if (ht!=null) {
		ht.innerHTML = "";    
	}
	return
}

function hoba_put_key(origin,key,alg) 
{
	var encval=JSON.stringify(key);
	try {
		hoba_setpriv(encval);
	} catch(e) {
		hobatext("Storage exception");
	}
	return true;
}

function regcallback() 
{
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
	hoba_show_state();
}

function unregcallback() 
{
	if (unregreq.readyState == 4 && unregreq.status == 200) {                
		hobatext(unregreq.responseText);
	} else if (regreq.readyState == 4 && regreq.status >= 400) {                
		hobatext(unregreq.responseText);
	}
	hoba_show_state();
}

function authcallback() 
{
	if (authreq.readyState == 4 && authreq.status == 200) {                
		hobatext(authreq.responseText);
	} else if (authreq.readyState == 4 && authreq.status >= 400) {                
		hobatext("HTTP-" + authreq.status + ": " + authreq.responseText);
	}
	hoba_show_state();
}

function add0D0As(str)
{
	var out="";
	for (i=0;i!=str.length;i++) {
		out+=str[i];
		if (i && ((i%64)==0)) {
			out+="%0D%0A";
		}
	}
	return out;
}




function hoba_login() 
{
  var authres=hoba_make_auth_header();
  // and send it
  authreq=new XMLHttpRequest();
  var regloc="/.well-known/hoba/login";
  authreq.onreadystatechange = authcallback;
  authreq.open('POST',regloc,true);
  authreq.setRequestHeader("Authorization","HOBA "+authres);
  authreq.send(null);
}

function hoba_logout() 
{
	var authres=hoba_make_auth_header();
	// and send it
	authreq=new XMLHttpRequest();
	var regloc="/.well-known/hoba/logout";
	authreq.onreadystatechange = authcallback;
	authreq.open('POST',regloc,true);
	authreq.setRequestHeader("Authorization","HOBA "+authres);
	authreq.send(null);
}

function hoba_register() 
{
	// 0=sha256 ; 1=sha-1
	var alg=0;
	var origin=get_origin();
	var tbsorigin=get_tbsorigin();
	// have we a key for that origin? if not generate one
	privstruct=hoba_get_key(origin,alg);
	if (!ismsie && privstruct==false) {
		hobatext("waiting key generation completion - will try again in a second");
		setTimeout(hoba_register,1000);
		return false;
	}
	if (privstruct.state!="new" && privstruct.state!="reginwork")  {
		// odd dunno why we're here, just quit
		if (privstruct.state="regok") {
			hobatext("Already registered dude.");
		} else {
			hobatext("Weirdness in registration.");
		}
		return;
	}
	var pem_prefix="-----BEGIN PUBLIC KEY-----";
	var pem_spki=urlb64(hex2b64(hoba_get_spki(privstruct.rsa)));
	// add a line break after each 64 chars
	pem_spki=add0D0As(pem_spki);
	var pem_postfix="-----END PUBLIC KEY-----";
	var pem_str=pem_prefix + "%0D%0A" + pem_spki + "%0D%0A" + pem_postfix;
	var regparams="&kidtype="
					+privstruct.kidalg
					+"&kidval=" 
					+urlb64(privstruct.kid)
					+"&didtype=2&didval=youpick&pub="
					+pem_str;
	regreq=new XMLHttpRequest();
	var regloc="/.well-known/hoba/register";
	regreq.onreadystatechange = regcallback;
	regreq.open('POST',regloc,true);
	regreq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	var authres=hoba_make_auth_header();
	regreq.setRequestHeader("Authorization","HOBA "+authres);
	regreq.send(regparams);
}

function hoba_getmykid()
{
	var alg=0;
	var ignoredOrigin="Somewhere"; // ignored currently, figure out if need be
	privstruct=hoba_get_key(ignoredOrigin,alg);
	return privstruct.kid;
}

function hoba_checkUA() 
{
	// is this msie?
	var appName=navigator.appName;
	if (appName=="Microsoft Internet Explorer") {
		ismsie=true;
	}
	clearhobatext();
	hobatext("Checking browser is HOBA compatible...");
	var goodEnough=false;
	var bad_str=""; 
	try {
		var storageok=false;
		if (localStorage) {
			localStorage.setItem("hoba_test","hoba_test");
			var ht=localStorage.getItem("hoba_test");
			if (ht!="hoba_test")  {
				bad_str="write/read error";
			} else {
				storageok=true;
				localStorage.removeItem("hoba_test");
			}
		}
		// can we use a web worker?
		if (storageok) bad_str="worker problem";
		goodEnough=storageok;
		if (!ismsie && window.Worker) {
			worker = new Worker('/js/worker-min.js');
			if (worker) {
				worker.addEventListener('message', function(e) {
					var data=e.data;
					if (data.iskey) {
						hoba_setpriv(data.key);
						hobatext("Key stored.");
					} else if (data.issig) {
						cachedsig=data.sig;
						cachedsigtime=new Date();
						hobatext("Got sig from worker");
					} else if (data.msg) {
						hobatext("Worker said: " + data.msg);
					} else {
						hobatext("garbled worker msg: " + e.data);
					}
				}, false);
				worker.addEventListener('error',function(e) {
					hobatext("Worker error: " + e.filename + ":" + e.lineno + "," + e.message);
				}, false);
				workerok=true;
			}
		}
		if (!workerok) {
			hobatext("No background worker (sorry)");
			worker=null;
		}
		// if work
		var val=hoba_getpriv();
		// figure out web origin, as scheme:auth:port (no slashes)
		var origin=get_origin();
		var tbsorigin=get_tbsorigin();
		var alg=0;
		if (!workerok && (val==null || val==undefined)) {
			// generate key
			val=hoba_get_key(origin,alg);
		}
		if (workerok && val==null) {
			// ask worker to generate a key
			var foo={ 'cmd': 'gen', 'alg': alg,'origin': origin};
			worker.postMessage(foo);
		}
		if (!workerok) {
			hobatext("No background worker (sorry)");
		}
		if (workerok && val!=null && bgsigning) {
			// ok let's try turn on background signing
			privstruct=hoba_get_key(origin,alg);
			if (privstruct) {
				hobatext("worker will background sign");
				var foo={ 'cmd': 'bgsign', 'alg': alg,'origin': origin,'tbsorigin':tbsorigin, 
							'n': privstruct.n,'e': privstruct.e, 'd':privstruct.d,'kid':urlb64(privstruct.kid)};
				worker.postMessage(foo);
			} else {
				hobatext("no background signing - waiting for key generation");
				hobatext("a reload after key gen done will fix");
			}
		}
	} catch (e) {
		bad_str=e.message;
	}
	//window.setTimeout(hoba_checkUA_update,2000);
	if (!goodEnough) {
		hobatext("Checking browser is HOBA compatible...sorry doesn't seem to work." 
				+ bad_str) ;
	} else {
		hobatext("Checking browser is HOBA compatible...seems fine, great!");
	}
	hoba_show_state();
}

function hoba_unreg() 
{
	hobatext("I'm gonna (try) delete your key!");
	var goodEnough=false;
	var bad_str=""; 
	var alg=0;
	var priv;
	try {
		if (localStorage) {
			var val=hoba_getpriv();
			if (val!=null) {
				priv=JSON.parse(val);
				if (priv.state=="regok") {
					/// todo ask yes/no to be sure
					var authres=hoba_make_auth_header();
					unregreq=new XMLHttpRequest();
					var regloc="/.well-known/hoba/unregister";
					unregreq.onreadystatechange = unregcallback;
					unregreq.open('POST',regloc,true);
					unregreq.setRequestHeader("Authorization","HOBA "+authres);
					unregreq.send(null);
				} 
				hoba_delpriv();
				goodEnough=true;
				// ask worker to generate a key
				var foo={ 'cmd': 'gen', 'alg': alg,'origin': priv.origin};
				worker.postMessage(foo);
			}
		}
	} catch (e) {
		bad_str=e.message;
	}
	if (!goodEnough) {
		hobatext("Sorry - deleting failed: " + bad_str);
	} else {
		hobatext("Deleted Key: " + priv.kid) ;
	}
}

function hoba_showkid() 
{
	hobatext("I'm gonna (try) show yor your public key!");
	var goodEnough=false;
	var bad_str=""; 
	var alg=0;
	var lskey="priv:"+alg;
	var priv;
	try {
		if (localStorage) {
			var val=hoba_getpriv();
			if (val!=null) {
				goodEnough=true;
			}
			priv=JSON.parse(val);
		}
	} catch (e) {
		bad_str=e.message;
	}
	//window.setTimeout(hoba_checkUA_update,2000);
	if (!goodEnough) {
		hobatext("Sorry - reading failed: " + bad_str) ;
	} else {
		hobatext("Your Key for " + this.location + " has Key ID: " + priv.kid + 
				" and was created at: " + priv.time + 
				" and is in state: " + priv.state) ;
	}
}

function ReadCookie(cookieName) {
 var theCookie=" "+document.cookie;
 var ind=theCookie.indexOf(" "+cookieName+"=");
 if (ind==-1) ind=theCookie.indexOf(";"+cookieName+"=");
 if (ind==-1 || cookieName=="") return "";
 var ind1=theCookie.indexOf(";",ind+1);
 if (ind1==-1) ind1=theCookie.length; 
 return unescape(theCookie.substring(ind+cookieName.length+2,ind1));
}

function hoba_show_buttons(state,regstate)
{
	var libut='<input id="login-button" type="button" value="Login" \
		class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		onmouseout="hov(this,\'btn\')"  \
		onClick="hoba_login();"/>';
	var lobut='<input id="logout-button" type="button" value="Logout"  \
		class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		onmouseout="hov(this,\'btn\')"  \
		onClick="hoba_logout();" /> ';
	var regbut='<input id="reg-button" type="button" value="Register"  \
		class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		onmouseout="hov(this,\'btn\')"  \
		onClick="hoba_register();"/> ';
	//var aclink='<input id="ac-button" type="button" value="Account"  \
		//class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		//onmouseout="hov(this,\'btn\')"  \
		//onClick="parent.location=\'/account.html\'"/> ';
	//var aclink='<a href="/account.html">Account</a>';
	var aclink="";

	var spot=document.getElementById("buttons");
	if (!spot) return;
	if (regstate=='regok') {
		if (state=='Loggedin') {
			spot.innerHTML = aclink + lobut ;
		} else {
			spot.innerHTML = aclink + libut ;
		}
	} else {
		if (regstate=='new') {
			spot.innerHTML=regbut;
		} else {
			spot.innerHTML="<p>Please reload</p>";
		} 
	}

}

function hoba_show_state()
{
	var regstate="dunno";
	var alg=0;
	var val=hoba_getpriv();
	if (val!=null) {
		var lpriv=JSON.parse(val);
		regstate=lpriv.state;
	}
	var loginstate=ReadCookie('HOBAState');
	hoba_show_buttons(loginstate,regstate);
	if (ismsie) {

		if (loginstate=="Loggedin") {
			if (document.getElementById("login-state")) {
				document.getElementById("login-state").innerHTML =    
					"<img src=\"/greentick-small.png\" alt=\"You are logged in\"/>";
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
			if (document.getElementById('logout-button')) {
				document.getElementById('logout-button').disabled = false;
			}
		} else {
			if (document.getElementById("login-state")) {
				document.getElementById("login-state").innerHTML =    
					"<img src=\"/redx-small.png\" alt=\"You are logged out\"/>";
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = false;
			}
			if (document.getElementById('logout-button')) {
				document.getElementById('logout-button').disabled = true;
			}
		}
		if (regstate=="regok") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = false;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
		} else if (regstate=="reginwork") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = false;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		} else if (regstate=="new") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = false;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = true;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		} else {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = true;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = true;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		}

	} else {

		if (loginstate=="Loggedin") {
			if (document.getElementById("login-state")) {
				document.getElementById("login-state").innerHTML =    
					"<img src=\"/greentick-small.png\" alt=\"You are logged in\"/>";
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
			if (document.getElementById('logout-button')) {
				document.getElementById('logout-button').disabled = false;
			}
		} else {
			if (document.getElementById("login-state")) {
				document.getElementById("login-state").innerHTML =    
					"<img src=\"/redx-small.png\" alt=\"You are logged out\"/>";
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = false;
			}
			if (document.getElementById('logout-button')) {
				document.getElementById('logout-button').disabled = true;
			}
		}
		if (regstate=="regok") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = false;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
		} else if (regstate=="reginwork") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = false;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		} else if (regstate=="new") {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = false;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = true;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = false;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		} else {
			if (document.getElementById('reg-button')) {
				document.getElementById('reg-button').disabled = true;
			}
			if (document.getElementById('unreg-button')) {
				document.getElementById('unreg-button').disabled = true;
			}
			if (document.getElementById('show-button')) {
				document.getElementById('show-button').disabled = true;
			}
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		}
	}

	// case of account.html regwarn element
	var rw=document.getElementById('regwarn');
	var acbodregbut='<input id="acbod-reg-button" type="button" value="Register"  \
		class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		onmouseout="hov(this,\'btn\')"  \
		onClick="hoba_register();"/> ';
	var refreshbut='<input id="acbod-reg-button" type="button" value="Refresh"  \
		class="btn" onmouseover="hov(this,\'btn btnhov\')"  \
		onmouseout="hov(this,\'btn\')"  \
		onClick="history.go(0);"/> ';
	if (regstate!="regok" && rw) {
		rw.innerHTML="You're not registered - Please" + acbodregbut + " and then " + refreshbut + " this page.";
	} 
}

// this deletes the cookie when called
function DeleteCookie( name, path, domain ) {
if ( ReadCookie( name ) ) document.cookie = name + "=" +
( ( path ) ? ";path=" + path : "") +
( ( domain ) ? ";domain=" + domain : "" ) +
";expires=Thu, 01-Jan-1970 00:00:01 GMT";
}

function hoba_testprng()
{
	var prngurl="/.well-known/hoba/testprng";
	hobatext("those to " + prngurl);
	hobatext("To do that I'll generate some random numbers and send");
	hobatext("Gonna test Pseudo-Random Number Generator on this device");

	var rng=new SecureRandom();
	var ra=new Array(); 
	ra.length=8000;
	rng.nextBytes(ra);
 	var rReq = new XMLHttpRequest();
  	rReq.onload = function() {
		if (rReq.readyState == 4 && rReq.status == 200) {
			hobatext(this.responseText);
		} else if (rReq.readyState == 4 && rReq.status >= 400) {
			hobatext("ERROR: " + this.responseText);
		}
  	};
	rReq.open('POST',prngurl,true);
	rReq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	var params="&rndstr="+ra;
	rReq.send(params);
}

function hoba_zap()
{
	hobatext("Asked to zap");
	var reallysure=confirm("Do you really want to delete your keys?");
	if (reallysure) {
		/// kill all stored content
		hoba_delpriv();
		localStorage.removeItem("hoba_test");
		DeleteCookie('HOBAState');
		document.getElementById('reg-button').disabled = false;
		document.getElementById('unreg-button').disabled = true;
		document.getElementById('show-button').disabled = true;
		document.getElementById('login-button').disabled = true;
		hobatext("Zapped it all. Back to zero.");
	} else {
		hobatext("No zapping - user changed her mind");
	}
}

//document.onreadystatechange=hoba_show_state;

// Sign and submit any form with a HOBA header
// see https://DOMSTR/account.html for an example usage
// inspired by:  
// https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Using_XMLHttpRequest#Using_FormData_objects

function sign_n_submit (oFormElement,responsePlace,handler) 
{
		  if (!oFormElement) { return; }
		  if (!oFormElement.action) { return; }
		  var oReq = new XMLHttpRequest();
		  var authres=hoba_make_auth_header();
		  oReq.onload = function() {
			if (oReq.readyState == 4 && oReq.status == 200) {
				if ( document.getElementById(responsePlace)) {
  					document.getElementById(responsePlace).innerHTML=this.responseText;
				}
				handler();
			} else if (oReq.readyState == 4 && oReq.status >= 400) {
				if ( document.getElementById(responsePlace)) {
  					document.getElementById(responsePlace).innerHTML=this.responseText;
				}
			}
		  }
		  if (oFormElement.method.toLowerCase() == "post") {
		    oReq.open("post", oFormElement.action, true);
		  	oReq.setRequestHeader("Authorization","HOBA " + authres);
			var fd=new FormData(oFormElement);
		    oReq.send(fd); 
		  } else {
		    var oField, sFieldType, nFile, sSearch = "";
		    for (var nItem = 0; nItem < oFormElement.elements.length; nItem++) {
		      oField = oFormElement.elements[nItem];
		      if (!oField.hasAttribute("name")) { continue; }
		      sFieldType = oField.nodeName.toUpperCase() === "INPUT" ? oField.getAttribute("type").toUpperCase() : "TEXT";
		      if (sFieldType === "FILE") {
		        for (nFile = 0; nFile < oField.files.length; sSearch += "&" + escape(oField.name) + "=" + escape(oField.files[nFile++].name));
		      } else if ((sFieldType !== "RADIO" && sFieldType !== "CHECKBOX") || oField.checked) {
		        sSearch += "&" + escape(oField.name) + "=" + escape(oField.value);
		      }
		    }
		    oReq.open("get", oFormElement.action.replace(/(?:\?.*)?$/, sSearch.replace(/^&/, "?")), true);
		  	oReq.setRequestHeader("Authorization","HOBA " + authres);
		    oReq.send(null);
		  }
}

// Another go at this, with a bit more info 
function hoba_checkUA2() 
{
	// is this msie?
	var appName=navigator.appName;
	if (appName=="Microsoft Internet Explorer") {
		ismsie=true;
	}
	clearhobatext();
	hobatext("Checking browser is HOBA compatible...");
	var goodEnough=false;
	var bad_str=""; 
	try {
		var storageok=false;
		if (localStorage) {
			localStorage.setItem("hoba_test","hoba_test");
			var ht=localStorage.getItem("hoba_test");
			if (ht!="hoba_test")  {
				bad_str="write/read error";
			} else {
				storageok=true;
				localStorage.removeItem("hoba_test");
			}
		}
		// can we use a web worker?
		if (storageok) bad_str="worker problem";
		goodEnough=storageok;
		if (!ismsie && window.Worker) {
			worker = new Worker('/js/worker-min.js');
			if (worker) {
				worker.addEventListener('message', function(e) {
					var data=e.data;
					if (data.iskey) {
						hoba_setpriv(data.key);
						hobatext("Key stored.");
					} else if (data.issig) {
						cachedsig=data.sig;
						cachedsigtime=new Date();
						hobatext("Got sig from worker");
					} else if (data.msg) {
						hobatext("Worker said: " + data.msg);
					} else {
						hobatext("garbled worker msg: " + e.data);
					}
				}, false);
				worker.addEventListener('error',function(e) {
					hobatext("Worker error: " + e.filename + ":" + e.lineno + "," + e.message);
				}, false);
				workerok=true;
			}
		}
		if (!workerok) {
			hobatext("No background worker (sorry)");
			worker=null;
		}
		// if work
		var val=hoba_getpriv();
		// figure out web origin, as scheme:auth:port (no slashes)
		var origin=get_origin();
		var tbsorigin=get_tbsorigin();
		var alg=0;
		if (!workerok && (val==null || val==undefined)) {
			// generate key
			val=hoba_get_key(origin,alg);
		}
		if (workerok && val==null) {
			// ask worker to generate a key
			var foo={ 'cmd': 'gen', 'alg': alg,'origin': origin};
			worker.postMessage(foo);
		}
		if (!workerok) {
			hobatext("No background worker (sorry)");
		}
		if (workerok && val!=null && bgsigning) {
			// ok let's try turn on background signing
			privstruct=hoba_get_key(origin,alg);
			if (privstruct) {
				hobatext("worker will background sign");
				var foo={ 'cmd': 'bgsign', 'alg': alg,'origin': origin,'tbsorigin':tbsorigin, 
							'n': privstruct.n,'e': privstruct.e, 'd':privstruct.d,'kid':urlb64(privstruct.kid)};
				worker.postMessage(foo);
			} else {
				hobatext("no background signing - waiting for key generation");
				hobatext("a reload after key gen done will fix");
			}
		}
	} catch (e) {
		bad_str=e.message;
	}
	//window.setTimeout(hoba_checkUA_update,2000);
	if (!goodEnough) {
		hobatext("Checking browser is HOBA compatible...sorry doesn't seem to work." 
				+ bad_str) ;
	} else {
		hobatext("Checking browser is HOBA compatible...seems fine, great!");
	}
	hoba_show_state();
}

// this is a short-term workaround, otherwise get an infinite loop
// if you load account.html before registration (login gets a 500
// HTTP result)
var loginfailcount=0;

function populate_ac() 
{
		hoba_checkUA();
		var loginstate=ReadCookie('HOBAState');
		var regstate="dunno";
		var val=hoba_getpriv();
		if (val!=null) {
			var lpriv=JSON.parse(val);
			regstate=lpriv.state;
		}
		if (regstate!="regok") {
			hoba_show_state();

			return;
		}
		if (regstate=="regok" && loginfailcount < 10 && loginstate!='Loggedin') {
			loginfailcount++;
			hoba_login();
			setTimeout(populate_ac,100);
			return;
		}
		var rp=document.getElementById('resplace');
		if (rp) {
			rp.innerHTML="populating...";
		}
		var theform=document.getElementById('acidTable');
		if (theform) {
			theform.rows[1].cells[0].innerHTML=
				"<td> <input name =\"txt[]\" type=\"text\" value=\"bogus@example.com\"/> </td>";
		}
		var oReq = new XMLHttpRequest();
		//var authres=hoba_make_auth_header();
		oReq.onload = function() {
			if (oReq.readyState == 4 && oReq.status == 200 && oReq.responseText!="") {
				var resparr=JSON.parse(oReq.responseText);
				if (document.getElementById("hiddenfield")) {
					var hinput='<input name="hf" type="hidden" value="' + resparr.hf + '"/>';
					document.getElementById("hiddenfield").innerHTML=hinput;
				}
				if (resparr!=null) {
					var table=document.getElementById('acidTable');
					var tbody=table.getElementsByTagName("tbody")[0];
					var rowCount = tbody.rows.length;
					for (var i in resparr.ids) {
						var row;
						if (i>=rowCount) {
							row = tbody.insertRow(i);
						} else {
							row=tbody.rows[i];
						}
						var idtype=resparr.ids[i][0];
						var idval=resparr.ids[i][1];
						if (idtype=='email') {
							row.innerHTML=
								'<tr>\
								<td> <input name ="txt[]" type="text" value="'+idval+'"/> </td>\
								<td><select name="type[]">\
								<option selected value="email">email</option>\
								<option value="tel">phone</option>\
								<option value="xmpp">xmpp</option>\
								<option value="jabber">jabber</option>\
								<option value="sms">sms</option>\
								</select>\
								</td>\
								<td><input type="checkbox" name="chk[]"/></td>\
							</tr>';
						}
						if (idtype=='tel') {
							row.innerHTML=
								'<tr>\
								<td> <input name ="txt[]" type="text" value="'+idval+'"/> </td>\
								<td><select name="type[]">\
								<option value="email">email</option>\
								<option selected value="tel">phone</option>\
								<option value="xmpp">xmpp</option>\
								<option value="jabber">jabber</option>\
								<option value="sms">sms</option>\
								</select>\
								</td>\
								<td><input type="checkbox" name="chk[]"/></td>\
							</tr>';
						}
						if (idtype=='xmpp') {
							row.innerHTML=
								'<tr>\
								<td> <input name ="txt[]" type="text" value="'+idval+'"/> </td>\
								<td><select name="type[]">\
								<option value="email">email</option>\
								<option value="tel">phone</option>\
								<option selected value="xmpp">xmpp</option>\
								<option value="jabber">jabber</option>\
								<option value="sms">sms</option>\
								</select>\
								</td>\
								<td><input type="checkbox" name="chk[]"/></td>\
							</tr>';
						}
						if (idtype=='jabber') {
							row.innerHTML=
								'<tr>\
								<td> <input name ="txt[]" type="text" value="'+idval+'"/> </td>\
								<td><select name="type[]">\
								<option value="email">email</option>\
								<option value="tel">phone</option>\
								<option value="xmpp">xmpp</option>\
								<option selected value="jabber">jabber</option>\
								<option value="sms">sms</option>\
								</select>\
								</td>\
								<td><input type="checkbox" name="chk[]"/></td>\
							</tr>';
						}
						if (idtype=='sms') {
							row.innerHTML=
								'<tr>\
								<td> <input name ="txt[]" type="text" value="'+idval+'"/> </td>\
								<td><select name="type[]">\
								<option value="email">email</option>\
								<option value="tel">phone</option>\
								<option value="xmpp">xmpp</option>\
								<option value="jabber">jabber</option>\
								<option selected value="sms">sms</option>\
								</select>\
								</td>\
								<td><input type="checkbox" name="chk[]"/></td>\
							</tr>';
						}
					}

					table=document.getElementById('devTable');
					var tbody=table.getElementsByTagName("tbody")[0];
					rowCount = tbody.rows.length;
					for (var i in resparr.kids) {
						var row;
						if (i>=rowCount) {
							row = tbody.insertRow(i);
						} else {
							row=tbody.rows[i];
						}
						var kidval=resparr.kids[i][0];
						var didval=resparr.kids[i][1];
						row.innerHTML=
								'<tr>\
								<td> <input name ="devid[]" type="text" value="'+didval+'"/> </td>\
								<td> <input size="5" readonly="yes" name ="keyid[]" type="text" value="'+kidval+'"/> </td>\
								<input type="hidden" name="deldev[]" value="0"/>\
								<td><input type="checkbox" name="deldev[]"/></td>\
								</td>\
								</tr>';
					}

					if (resparr.kids==undefined || resparr.kids.length==0) {
						row=tbody.rows[0];
						var uastring=navigator.userAgent;
						var mykid=hoba_getmykid();
						row.innerHTML=
								'<tr>\
								<td> <input name ="devid[]" type="text" value="'+uastring+'"/> </td>\
								<td> <input size="5" readonly="yes" name ="keyid[]" type="text" value="'+mykid+'"/> </td>\
								<input type="hidden" name="deldev[]" value="0"/>\
								<td><input type="checkbox" name="deldev[]"/></td>\
								</td>\
								</tr>';
					}
				}
				document.getElementById('resplace').innerHTML += "populated";
			} else if (oReq.readyState == 4 && oReq.status >= 400 && oReq.status < 499 ) {
				document.getElementById('resplace').innerHTML = "Oops";
				if (document.getElementById('regwarn')) {
					document.getElementById('regwarn').innerHTML="Login expired ("+oReq.status+") - Try login afresh.";
				}
				// consider yourself logged out too
				DeleteCookie('HOBAState');
			}
			hoba_show_state();
		}
		oReq.open("GET", "/.well-known/hoba/acinfo?justget=yes", true);
		//oReq.setRequestHeader("Authorization","HOBA "+authres);
		oReq.send();
		hoba_show_state();
}

function refresh_ac()
{
	table=document.getElementById('devTable');
	var tbody=table.getElementsByTagName("tbody")[0];
	rowCount = tbody.rows.length;
	for (var i=0;i<rowCount;i++) {
		var row=tbody.rows[i];
		// note: the "2" below depends on account.html and populate_ac code above
		var deleted = row.cells[2].childNodes[0];
		if(null != deleted && true == deleted.checked) {
			tbody.deleteRow(i);
			rowCount--;
			i--;
		}
	}
}
*/

module.exports = {
/*
  get_key: function hoba_get_key(alg){
    // localStorage key
    var lskey="priv:"+alg;
    if (typeof(localStorage)=='undefined') return false;
    var val=hoba_getpriv();
    if (val==null) {
      
      if (ismsie || (worker==null || keygenfails>10)) { // do it in line
	// generate a key pair and store stuff
	val=hoba_gen_key(origin,alg);
	if (val!=false) {
	  hoba_setpriv(val);
	} else {
	  return false;
	}
      } else {
	keygenfails++;
	return false;
      }
    } 
    var decval=JSON.parse(val);
    var splitres=decval.priv.split(":");
    decval.n=splitres[0];
    decval.e=splitres[1];
    decval.d=splitres[2];
    decval.rsa=new RSASetPrivate(decval.n,decval.e,decval.d);
    return decval;
  },

  make_auth_header: function hoba_make_auth_header(){
    return hoba_make_auth_header_chal(null);
  },
*/
  
  make_auth_header_chal: function hoba_make_auth_header_chal(provided_chal){
    dump("\nEntering hoba_make_auth_header_chal()")
    // ask worker maybe
    var usedcache=false;
    
    var origin=get_origin();
    dump("\nFinished get_origin()")
    var tbsorigin=get_tbsorigin();
    dump("\nFinished get_tbsorigin()")
    
    var sig2use;
    // check if worker has work done for me
    if (workerok && bgsigning) {
      var now=new Date();
      var sigage=now.getTime()-cachedsigtime.getTime();
      if (cachedsig!="" && sigage<maxchalwindow) {
	hobatext("using signature that's " + sigage + "ms old");
	//hobatext("That sig is: " + cachedsig);
	sig2use=cachedsig;
	cachedsig="";
	cachedsigtime=new Date();
	usedcache=true;
      }
    }
    // 0=sha256 ; 1=sha-1
    var alg=0;
    // have we a key for that origin? if not generate one
    privstruct=hoba_get_key(origin,alg);
    if (privstruct==false) {
      hobatext("waiting for key generation");
      return false;
    }
    
    if (!usedcache) {
      if (provided_chal!=null) {
	sig2use=make_auth_header_aux_chal(provided_chal,alg,origin,tbsorigin,
					  privstruct.n,
					  privstruct.e,
					  privstruct.d,
					  urlb64(privstruct.kid));
      } else {
	sig2use=make_auth_header_aux(alg,origin,tbsorigin,
				     privstruct.n,
				     privstruct.e,
				     privstruct.d,
				     urlb64(privstruct.kid));
      }
    } else {
      // tee up another sig
      hobatext("handed private to worker");
      var foo={ 'cmd': 'bgsign', 'alg':alg,'origin': origin,'tbsorigin':tbsorigin, 
		'n': privstruct.n,'e': privstruct.e, 'd':privstruct.d,'kid':urlb64(privstruct.kid)};
      // kick off another signature gen in 2 seconds
      setTimeout(worker.postMessage(foo),2000);
    }
    return sig2use;
  },

  // figure out web origin, as scheme:auth:port (no slashes)
  get_origin: function get_origin(uri){
    dump("\nEntering get_origin()");
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

  /*
  get_tbsorigin: function get_tbsorigin(){
    dump("\nEntering get_tbsorigin()")
    // figure out web origin, as scheme://auth:port (now with slashes:-)
    var wo=location;
    var tbsorigin = wo.protocol;
    if (tbsorigin.charAt(tbsorigin.length-1)==":") {
      tbsorigin=tbsorigin.substring(0,tbsorigin.length-1);
    }
    tbsorigin+="://"+wo.hostname;
    if (wo.port===null || wo.port==null || wo.port=="") {
      if (wo.protocol=="http:") {
	tbsorigin+=":80";
      } else if (wo.protocol=="https:") {
	tbsorigin+=":443";
      } 
    } else {
      // non null port - add it on
      tbsorigin+=":"+wo.port;
    }
    return tbsorigin;
  }
*/
};
