/*!
 * @file binding.js
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

function hoba_binding(btype,place)
{
	// make up a sig...
	var authres=hoba_make_auth_header();
	// want this to know if we're in the same place
	// var myipaddr= whatever - I forget why I wanted that;-)
	// swoop up input values
	var duration=document.getElementById('bindDuration').value;
	// var scode=document.getElementById('bindShortCode').value;
	var scode="no thanks";
	var email="";
	if (document.getElementById('contact')) {
		email=document.getElementById('contact').value;
	}
	if (btype=="email" && email=="") {
		alert("You need to enter an email address");
		return;
	}
	// make up a FormData
	// and send it
	var bindreq=new XMLHttpRequest();
	var bindloc="/.well-known/hoba/binding";
	bindreq.open('POST',bindloc,true);
	bindreq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	bindreq.setRequestHeader("Authorization","HOBA " + authres);
	bindreq.onload = function() {
		document.getElementById(place).innerHTML=bindreq.responseText;
		//alert("type: " + btype +
			 //"\nput result at: " + place +
			 //"\nduration: " + duration +
			 //"\nscode: " + scode + 
			 //"\nemail: " + email +
			//"\nans: " + bindreq.responseText);
	}
	var fdata="btype="+btype+
				"&duration="+duration+
				"&scode="+scode+
				"&ctype=email"+
				"&contact="+email;
	bindreq.send(fdata);
}

