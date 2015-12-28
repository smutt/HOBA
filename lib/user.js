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

/*
function hobatext(str)
{
	return;
}

function clearhobatext()
{
	return;
}
*/


function hoba_show_state()
{
	var regstate="dunno";
	var val=hoba_getpriv();
	if (val!=null) {
		var lpriv=JSON.parse(val);
		regstate=lpriv.state;
	}
	var loginstate=ReadCookie('HOBAState');
	
	if (ismsie) {
		if (loginstate=="Loggedin") {
			document.getElementById("login-state").innerHTML =    
				"<img src=\"/greentick.png\" width=\"90%\" alt=\"You are logged in\"/><p>Logged in.</p>";
			document.getElementById('login-button').disabled = true;
			document.getElementById('logout-button').disabled = false;
		} else {
			document.getElementById("login-state").innerHTML =    
				"<img src=\"/redx.png\" width=\"90%\" alt=\"You are logged out\"/><p>Logged out.</p>"
			document.getElementById('login-button').disabled = false;
			document.getElementById('logout-button').disabled = true;
		}
		if (regstate=="regok") {
			var foo=1;
		} else if (regstate=="reginwork") {
			document.getElementById('login-button').disabled = true;
		} else if (regstate=="new") {
			document.getElementById('login-button').disabled = true;
		} else {
			document.getElementById('login-button').disabled = true;
		}
	} else {
		if (loginstate=="Loggedin") {
			document.getElementById("login-state").innerHTML =    
				"<img src=\"/greentick.png\" width=\"90%\" alt=\"You are logged in\"/><p>Logged in.</p>";
			document.getElementById('login-button').disabled = true;
			document.getElementById('logout-button').disabled = false;
		} else {
			if (document.getElementById("login-state")) {
				document.getElementById("login-state").innerHTML =    
					"<img src=\"/redx.png\" width=\"90%\" alt=\"You are logged out\"/><p>Logged out.</p>"
				document.getElementById('login-button').disabled = false;
				document.getElementById('logout-button').disabled = true;
			}
		}
		if (regstate=="regok") {
			var foo=1;
		} else if (regstate=="reginwork") {
			document.getElementById('login-button').disabled = true;
		} else if (regstate=="new") {
			document.getElementById('login-button').disabled = true;
		} else {
			if (document.getElementById('login-button')) {
				document.getElementById('login-button').disabled = true;
			}
		}
	}
}

function checkGen()
{
	hoba_checkUA()
	if (localStorage) {
		var thing=hoba_getpriv();
		if (thing==null) { 
			// come back in a fifth (of a second)
			setTimeout(checkGen,200);
		}
	}
	hoba_register();
	hoba_show_state();
}
