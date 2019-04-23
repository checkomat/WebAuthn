'use strict';

// print function for communication data
function sf(obj) {
//	return JSON.stringify(publicKeyCredentialToJSON(obj), undefined, 2);
    return JSON.stringify(obj,function replacer(key,value){
		    if(value instanceof ArrayBuffer)
		        return base64url.encode(value)
        if(value instanceof Uint8Array)
          return base64url.encode(value);
        if((value instanceof Array) && value.length > 5)  	  //return arrayBufferToString(value);
          return base64url.encode(value);
        return value;
    },2);
}

var publicKeyCredentialToJSON = (pubKeyCred) => {
    if(pubKeyCred instanceof Array) {
        let arr = [];
        for(let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));
        return arr
    }

    if(pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    }

    if(pubKeyCred instanceof Object) {
        let obj = {};
        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }
        return obj
    }
    return pubKeyCred
}

// conversion functions

// to decode custom options received by RP ?
var preformatMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id   = base64url.decode(makeCredReq.user.id);

    return makeCredReq
}

// to decode custom options received by RP ??
var preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    
    for(let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }

    return getAssert
}

/* Converts a array buffer to a Array
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {Array}
*/
// https://stackoverflow.com/questions/54228277/convert-javascript-arraybuffer-to-array-of-8-bit-numbers/54228352
function arrayBufferToUint8Array(arrayBuffer) {
		let u8b = new Uint8Array(arrayBuffer).buffer; // array buffer
		let u8 = new Uint8Array(u8b);
		return u8;
//		return Array.from(u8);
}

/**
 * Converts a string to an ArrayBuffer
 * @param {string} string string to convert
 * @returns {ArrayBuffer}
 */
function stringToArrayBuffer(str){
    return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}

/**
 * Converts an array buffer to a UTF-8 string
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {string}
 */
function arrayBufferToString(arrayBuffer) {
    return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

/**
 * Concatenates array buffers
 * @private
 * @param {ArrayBuffers} buffer1
 * @param {ArrayBuffers} buffer2
 * @return {ArrayBuffers} The new ArrayBuffer created out of the two.
 */
function appendArrayBuffer( buffer1, buffer2 ) {
  var tmp = new Uint8Array( buffer1.byteLength + buffer2.byteLength );
  tmp.set( new Uint8Array( buffer1 ), 0 );
  tmp.set( new Uint8Array( buffer2 ), buffer1.byteLength );
  return tmp.buffer;
}

// mozilla experimental !
/*
var bufferToString = (buff) => {
    var enc = new TextDecoder(); // always utf-8
    return enc.decode(buff)
}
*/
var bufToHex = (buffer) => { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

let base64ToPem = (b64cert) => {
    let pemcert = '';
    for(let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + '\n';
    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

/**
 * Base64 encodes an array buffer
 * @param {ArrayBuffer} arrayBuffer 
 */
function base64encode(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.length == 0)
        return undefined;
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}


/**
 * Converts an base64url encoded buffer of the JSON to buffer to a UTF-8 string
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {string}
 */
// from https://webauthn.guide/
// https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770
var parseClientDataJSON = (buffer) => {
//	const utf8Decoder = new TextDecoder('utf-8')
//	const decodedClientData = utf8Decoder.decode(buffer)
		let s = String.fromCharCode.apply(null, new Uint8Array(buffer));
	// parse the string as an object
	return  JSON.parse(s);
}

// used for challenge instead of getChallenge()
var generateRandomBuffer = (length) => {
    if(!length)
        length = 32;

    var randomBuff = new Uint8Array(length);
    window.crypto.getRandomValues(randomBuff);
    return randomBuff
}

/**
 * Converts a COSE key to a JWK
 * @param {Buffer} cose Buffer containing COSE key data
 * @returns {any} JWK object
 */
const coseToJwk = cose => {
    try {
        let publicKeyJwk = {};
        const publicKeyCbor = CBOR.decode(cose);
				console.log(publicKeyCbor);

        if (publicKeyCbor[3] == -7) {
            publicKeyJwk = {
                kty: "EC",
                crv: "P-256",
                x: base64url.encode(publicKeyCbor[-2]),
                y: base64url.encode(publicKeyCbor[-3])
            }
        } else if (publicKeyCbor[3] == -257) {
            publicKeyJwk = {
                kty: "RSA",
                n: base64url.encode(publicKeyCbor[-1]),
                e: base64url.encode(publicKeyCbor[-2])
            }
        } else {
						console.log("coseToJwk: Unknown public key algorithm: " + publicKeyCbor[3]);
            throw new Error("Unknown public key algorithm");
        }

        return publicKeyJwk;
    } catch (e) {
				console.log("coseToJwk: Could not decode COSE Key: publicKeyCbor: " + publicKeyCbor);
        throw new Error("Could not decode COSE Key: " + e);
    }
}

/**
 * Parses AuthenticatorData
 * @param  {Uint8Array} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
// https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
// https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770
// https://w3c.github.io/webauthn/#authenticator-data
// Array attestationObject.authData: [RP ID hash | flags | counter | AAGUID | CredID | CredPubKey | Extensions]
var parseAuthData = (buffer) => { // expects Uint8Array

    if(buffer instanceof Uint8Array) {
			console.log('*AuthData is Uint8Array, length: ', buffer.length);
		}
		else if (buffer instanceof Array) {
			console.log('*AuthData is Array, length: ', buffer.length);	
    }
		else {
			console.log('*unexpected AuthData is not an Array');
		}

		if (buffer.length < 37) {
			console.log('*AuthData is too short, length: ', buffer.length);
		}

// SHA-256 hash of the RP ID the credential is scoped to. 
    let rpIdHash      = buffer.slice(0, 32);            buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);             buffer = buffer.slice(1);
    let flagsInt      = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01), // User Present (UP) result. 
        uv: !!(flagsInt & 0x04), // User Verified (UV) result.
        at: !!(flagsInt & 0x40), // Attested credential data included
        ed: !!(flagsInt & 0x80) // Extension data included
    }

    let counterBuf    = buffer.slice(0, 4);             buffer = buffer.slice(4);
    let counter       = readBE32(counterBuf);

		// RPIDHash, Flags and Counter is mandatory for both Attestation and Assertion responses. 
		// AttestedCredentialData is only for attestation.

    let aaguid        = undefined; // 16 bytes:  128-bit identifier indicating the type (e.g. make and model) of the authenticator.

		// Credential Identifier. The length is defined by credIdLen. Must be the same as id/rawId.
    let credID        = undefined; // 2 bytes: length L of Credential ID, 16-bit unsigned big-endian integer. 
		//COSE encoded public key
    let COSEPublicKey = undefined;

// compose attestedCredentialData
    if(flags.at) { // has attested credential data
        aaguid           = buffer.slice(0, 16);          buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);           buffer = buffer.slice(2);
//
        let credIDLen    = readBE16(credIDLenBuf);
        credID           = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
        COSEPublicKey    = buffer; // 77 bytes: coseEncodedCredentialPublicKey
    }

// todo test
		let extensionDataCbor;
		let extensionData = undefined;
		if(flags.ed) { //has extension data
      if (flags.at) {
          //if we have attestedCredentialData, then extension data is the second element
//          extensionDataCbor = cbor.decodeAllSync(authData.slice(55 + authenticatorData.attestedCredentialData.credentialIdLength, authData.length));
          extensionDataCbor = CBOR.decode(authData.slice(55 + authenticatorData.attestedCredentialData.credentialIdLength, authData.length));
          extensionDataCbor = extensionDataCbor[1];
      } else {
          //Else it's the first element
//          extensionDataCbor = cbor.decodeFirstSync(authData.slice(37, authData.length));
          extensionDataCbor = CBOR.decode(authData.slice(37, authData.length));
      }
      extensionData = base64encode(CBOR.encode(extensionDataCbor));
		}

		// attestedCredentialData = {aaguid, credID, COSEPublicKey}
    return {rpIdHash, flags, counter, aaguid, credID, COSEPublicKey, extensionData}
}


var getEndian = () => {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xAA; // set first byte
    uint8Array[1] = 0xBB; // set second byte

    if(uint16array[0] === 0xBBAA)
        return 'little';
    else
        return 'big';
}

var readBE16 = (buffer) => {
    if(buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint16Array(buffer.buffer)[0]
}

var readBE32 = (buffer) => {
    if(buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');

    if(getEndian() !== 'big')
        buffer = buffer.reverse();

    return new Uint32Array(buffer.buffer)[0]
}

