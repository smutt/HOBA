/*!
 * @file hoba-gen-key.js
 * @brief Javascript key generation used by hoba.js or worker.js
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

function ah2bin(ah) 
{
	// ascii-hex to binary
	var a = new Array();
	for(i = 0; 2*i < ah.length; ++i) {
		a[i] = parseInt(ah.substring(2*i,2*i+2),16);
	}
	return a;
}


function hoba_get_spki(key) 
{
	var modulus=key.n.toString(16)
	var keylen=modulus.length*4; // 4 bits per char for ascii-hex
	if (keylen==2048) {
		// this is the silly ASN.1 stuff for a 2048 bit rsa key that's before the modulus
		// assuming e=0x100001, this is what follows n
		var spki_prefix="30820122300d06092a864886f70d01010105000382010f003082010a0282010100";
		var spki_postfix="0203010001";
		var spki_ah=spki_prefix+modulus+spki_postfix;
	} else if (keylen==1024) {
		// this is the silly ASN.1 stuff for a 1024 bit rsa key that's before the modulus
		// assuming e=0x100001, this is what follows n
		var spki_prefix="30819f300d06092a864886f70d010101050003818d0030818902818100";
		var spki_postfix="0203010001";
		var spki_ah=spki_prefix+modulus+spki_postfix;
	} else {
		return 0;
	}
	return spki_ah;
}

function hoba_get_kid(key,alg) 
{
	// alg ignored for now 1=sha1, 0=sha-256 but I don't have that now;-)
	var spki=hoba_get_spki(key);
	var kid;
	if (alg==1) {
		kid=b64_sha1(spki);
	} else { // default of zero 
		kid=b64_sha256(spki);
	}
	return kid;
}

function hoba_keylen_for_device() 
{
	/// todo - change this to run a CPU test on startup
	if (navigator.userAgent) {
		var uas=navigator.userAgent;
		hobatext(uas);
		if (uas.match("iPhone")) { 
			return 1024;
		}
		if (uas.match("iPad")) { 
			return 1024;
		}
	}
	// else optimism and security !!
	return 1024;
}

function hoba_gen_key(origin,alg) 
{
	// origin is unused due to localStorage and SOP, might change with 
	// webcrypto, not sure yet, hence providing the input
	// using jsbn
	var keylen=hoba_keylen_for_device();
	hobatext("Generating a " + keylen + " bit RSA key pair");
	var rsa = new RSAKey();
	var before = new Date();
	rsa.generate(keylen,"10001");
	var after = new Date();
	var duration = after - before;
	hobatext("Done generating that " + keylen + " bit RSA key pair (took " + duration + "ms for that)");
	priv=rsa.n.toString(16) + ":" + rsa.e.toString(16) + ":" + rsa.d.toString(16);
	// our key storage object
	var val = new Object;
	val.state="new";
	val.alg=alg;
	val.time=after;
	val.origin=origin;
	val.priv=priv;
	val.kidalg=0;
	val.kid=hoba_get_kid(rsa,alg);
	var encval=JSON.stringify(val);
	return encval;
}


function urlb64(instr) 
{
	var out=""; 
	for(i = 0; i < instr.length; ++i) {
		if (instr[i]=='+') {
			out+='-';
		} else if (instr[i]=='/') {
			out+='_';
		} else {
			out+=instr[i];
		}
	}
	return(out);
}

var challenge;
var lastchaltime=0;

function getnewchal()
{
	var now=new Date();
	var nowmsec=now.getTime();
	var maxchalwindow=200000;
	var chalrefreshwindow=maxchalwindow/2;
	if ((nowmsec-lastchaltime)>chalrefreshwindow) {
		hobatext("background challenge");
		// async request
		var prechal = new XMLHttpRequest();
		prechal.open('POST', "/.well-known/hoba/getchal", false);
		prechal.onload = function () {
			if (prechal.readyState == 4 && prechal.status == 200 && prechal.getResponseHeader('HOBA') ) {
				challenge=prechal.getResponseHeader('HOBA').substring(5);
				now=new Date();
				lastchaltime=now.getTime();
			}
		}
		prechal.send(null);
	}
	if ((nowmsec-lastchaltime)<maxchalwindow) {
		// ok to use or re-use that one
		hobatext("re-used challenge");
		return challenge;
	}
	hobatext("synchronous challenge");
	// fall back to synchronous request if need be
	var newreq = new XMLHttpRequest();
	newreq.open('POST', "/.well-known/hoba/getchal", true);
	newreq.send(null);
	while (newreq.readyState!=4);
	if (newreq.getResponseHeader('HOBA')) {
		challenge=newreq.getResponseHeader('HOBA').substring(5);
		now=new Date();
		lastchaltime=now.getTime();
		return challenge;
	} else {
		return false;
	}
}

function make_auth_header_aux(alg,origin,tbsorigin,n,e,d,kid)
{
	var challenge = getnewchal(); 
	return make_auth_header_aux_chal(challenge,alg,origin,tbsorigin,n,e,d,kid);
}

function make_auth_header_aux_chal(challenge,alg,origin,tbsorigin,n,e,d,kid)
{
	// TBS = nonce alg origin realm kid challenge
	var na = new Array();
	na.length=8;
	rng_get_bytes(na);
	var bi=new BigInteger(na);
	var nah=bi.toString(16);
	var nonce = hex2b64(nah);
	if (nonce.charAt(nonce.length-1)=="=") {
		nonce=nonce.substring(0,nonce.length-1);
	}
	nonce=urlb64(nonce);
	var realm="";  // for later
	var ukid=urlb64(kid);
	var tbs=nonce+alg+tbsorigin+realm+ukid+challenge;
	// fire up signing
	/// todo clean up a LOT here - jsbn is fine, jsrsasign imports the world
	var sigrsa=new RSAKey();
	sigrsa.setPrivate(n,e,d);
	var sig;
	if (alg==1) {
		sig=sigrsa.signString(tbs,"sha1");
	} else {
		sig=sigrsa.signString(tbs,"sha256");
	}
	var b64sig=hex2b64(sig);
	b64sig=urlb64(b64sig);
	// make up a header and send that to get a page
	var authres="result=\"";
	authres+=urlb64(kid);
	authres+=".";
	authres+=challenge;
	authres+=".";
	authres+=nonce;
	authres+=".";
	authres+=b64sig;
	authres+="\"";
	return authres;
}
