/*!
 * @file user.js
 * @brief a "do all that's needed script"
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

function hoba_bindTo(bindval)
{
	// send a signed form to to ./well-known/hoba/binding?btype=res&bv=bindval
	var bReq = new XMLHttpRequest();
	var authres=hoba_make_auth_header();
	bReq.open("GET", "/.well-known/hoba/binding-res?btype=res&bv="+bindval, false);
	bReq.setRequestHeader("Authorization","HOBA " + authres);
	bReq.onload=function () {
		var  brnow=new Date();
	}
	bReq.send(null);
}

function hoba_register(bindval) 
{
	var alg=0;
	var origin=get_origin();
	var tbsorigin=get_tbsorigin();
	// have we a key for that origin? if not generate one
	privstruct=hoba_get_key(origin,alg);
	if (!ismsie && privstruct==false) {
		hobatext("waiting key generation completion - will try again in a second");
		setTimeout(function () {hoba_register(bindval)},1000);
		return false;
	}
	if (privstruct.state!="new" && privstruct.state!="reginwork")  {
		// odd dunno why we're here, just quit
		if (privstruct.state="regok") {
			hobatext("Already registered dude.");
			hoba_bindTo(bindval);
			hoba_login();
			hoba_show_state();
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
	regreq.onload = function () {
		if (regreq.readyState == 4 && regreq.status == 200) {                
			hobatext(regreq.responseText);
			privstruct.state="regok";
			privstruct.time=new Date();
			hoba_put_key(privstruct.origin,privstruct,privstruct.alg);
			hoba_bindTo(bindval);
			hoba_login();
			hoba_show_state();
		} else if (regreq.readyState == 4 && regreq.status >= 400) {                
			privstruct.state="reginwork";
			privstruct.time=new Date();
			hoba_put_key(privstruct.origin,privstruct,privstruct.alg);
			hobatext(regreq.responseText);
		}
		hoba_show_state();
	}
	regreq.open('POST',regloc,true);
	regreq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	regreq.send(regparams);
}

function getqrv() 
{
	var prmstr = window.location.search.substr(1);
	var prmarr = prmstr.split ("&");
	var params = {};
	for ( var i = 0; i < prmarr.length; i++) {
   		var tmparr = prmarr[i].split("=");
   		params[tmparr[0]] = tmparr[1];
		if (tmparr[0]=='qrv') return tmparr[1];
	}
	return ("dunno");
}

var cgstarted=false;

function checkGen()
{
	if (cgstarted) { return ; }
	cgstarted=true;
	hoba_checkUA()
	if (localStorage) {
		var thing=hoba_getpriv();
		if (thing==null) { 
			// come back in a fifth (of a second)
			setTimeout(checkGen,200);
		}
	}
	hoba_register(getqrv());
}



window.onload=function(){ 
	if (!window.document.body) {
		window.document.body.onload=checkGen; 
	} else {
		checkGen();
	}
}
