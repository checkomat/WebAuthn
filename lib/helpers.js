'use strict';

var generateRandomBuffer = (length) => {
    if(!length)
        length = 32;

    var randomBuff = new Uint8Array(length);
    window.crypto.getRandomValues(randomBuff);
    return randomBuff
}

// conversion functions

// ???
var preformatMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id   = base64url.decode(makeCredReq.user.id);

    return makeCredReq
}

// ???
var preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    
    for(let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }

    return getAssert
}


function sf(obj) {
    return JSON.stringify(obj,function replacer(key,value){
        if(value instanceof Uint8Array)
          return base64encode(value);
        if((value instanceof Array) && value.length > 5)  	  //return arrayBufferToString(value);
          return base64encode(value);
        return value;
    },2);
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
 * Converts an array buffer to a UTF-8 string
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {string}
 */
function arrayBufferToString(arrayBuffer) {
    return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

/* Converts a array buffer to a Array
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {Array}
*/
// https://stackoverflow.com/questions/54228277/convert-javascript-arraybuffer-to-array-of-8-bit-numbers/54228352
function arrayBufferToArray(arrayBuffer) {
		let u8b = new Uint8Array(arrayBuffer).buffer; // array buffer
		let u8 = new Uint8Array(u8b);
		return Array.from(u8);
}

/**
 * Converts a string to an ArrayBuffer
 * @param {string} string string to convert
 * @returns {ArrayBuffer}
 */
function stringToArrayBuffer(str){
    return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
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

/**
 * Converts a COSE key to a JWK
 * @param {Buffer} cose Buffer containing COSE key data
 * @returns {any} JWK object
 */
/*
const coseToJwk = cose => {
    try {
        let publicKeyJwk = {};
        const publicKeyCbor = cbor.decodeFirstSync(cose);

        if (publicKeyCbor.get(3) == -7) {
            publicKeyJwk = {
                kty: "EC",
                crv: "P-256",
                x: publicKeyCbor.get(-2).toString('base64'),
                y: publicKeyCbor.get(-3).toString('base64')
            }
        } else if (publicKeyCbor.get(3) == -257) {
            publicKeyJwk = {
                kty: "RSA",
                n: publicKeyCbor.get(-1).toString('base64'),
                e: publicKeyCbor.get(-2).toString('base64')
            }
        } else {
            throw new Error("Unknown public key algorithm");
        }

        return publicKeyJwk;
    } catch (e) {
        throw new Error("Could not decode COSE Key");
    }
}
*/

// parse functions for communication data

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

/**
 * Parses AuthenticatorData
 * @param  {Uint8Array} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
// https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
// https://w3c.github.io/webauthn/#authenticator-data
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
    let flagsInt      = flagsBuf[0]; // undefined?
    let flags = {
        up: !!(flagsInt & 0x01), // User Present (UP) result. 
        uv: !!(flagsInt & 0x04), // User Verified (UV) result.
        at: !!(flagsInt & 0x40), // Attested credential data included
        ed: !!(flagsInt & 0x80) // Extension data included
//        ,flagsInt
    }
		console.log('*rpIdHash: ', rpIdHash);
		console.log('*flags: ', flags);
		console.log('*rpIdHash: ', rpIdHash);

    let counterBuf    = buffer.slice(0, 4);             buffer = buffer.slice(4);
		console.log('*counterBuf: ', counterBuf);
    let counter       = readBE32(counterBuf);

    let aaguid        = undefined;
    let credID        = undefined;
    let COSEPublicKey = undefined;

    if(flags.at) { // has attested credential data
        aaguid           = buffer.slice(0, 16);          buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);           buffer = buffer.slice(2);
//
        let credIDLen    = readBE16(credIDLenBuf);
        credID           = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
        COSEPublicKey    = buffer;
    }

		let extensionDataCbor = undefined;
		if(flags.ed) { //has extension data
/*
      if (flags.at) {
          //if we have attesttestedCredentialData, then extension data is the second element
          extensionDataCbor = cbor.decodeAllSync(authData.slice(55 + authenticatorData.attestedCredentialData.credentialIdLength, authData.length));
          extensionDataCbor = extensionDataCbor[1];
      } else {
          //Else it's the first element
          extensionDataCbor = cbor.decodeFirstSync(authData.slice(37, authData.length));
      }

      authenticatorData.extensionData = cbor.encode(extensionDataCbor).toString('base64');
*/
		}

    return {rpIdHash, flags, counter, aaguid, credID, COSEPublicKey}
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



