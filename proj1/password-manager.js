"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray, stringToByteArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
//This pads with 100000... followed by zero (null) bytes. 
function rawToPaddedArray(arr,padded_length){
  let arr_length = arr.length;
  let bytes = [];
  for(let i = 0; i < arr_length; i++){
    bytes.push(arr[i]);
  }
  bytes.push(1);
  for(let i = arr_length+1; i < padded_length; i++){
    bytes.push(0);
  }
  return bytes;
};

function paddedArrayToRaw(arr,padded_length){
  let arr_length = padded_length;
  for(let i = padded_length-1; i >= 0; i--){
    if(arr[i] == 1){
      arr_length = i;
      break;
    }
  }
  return arr.slice(0,arr_length);
};

class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvs, salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
         kvs: kvs,
         salt: salt,
         HMACkey_pos: HMACkey_pos,//HMAC[masterkey,HMACkey_pos]
         HMACkey_signature: HMACkey_signature,
         AESGCMkey_pos: AESGCMkey_pos,
         AESGCMkey_signature: AESGCMkey_signature,
         HMACkey: HMACkey,
         AESGCMkey: AESGCMkey,
    };

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;

    //throw "Not Implemented!";
  };

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    
    //key derived from password using PBKDF2
    let rawKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    let salt = genRandomSalt();
    let masterKey = await subtle.deriveKey(
      {name:"PBKDF2", salt: salt, iterations: Keychain.PBKDF2_ITERATIONS, hash: "SHA-256"},
      rawKey,
      {name: "HMAC", hash: "SHA-256",length: 256},
      false,
      ["sign", "verify"]
      );
    
    //HMAC key for domain name
    //https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign#hmac
    let HMACkey_pos = genRandomSalt();
    let HMACkey_signature = await subtle.sign(
      "HMAC",
      masterKey,
      HMACkey_pos
    ); //datatype of HMACkey_signature is ArrayBuffer
    let HMACkey = await subtle.importKey(
      "raw",
      HMACkey_signature,
      {name: "HMAC", hash: "SHA-256"},
      false,
      ["sign"]
    );

    //AES-GCM key for passwords
    let AESGCMkey_pos = genRandomSalt();
    let AESGCMkey_signature = await subtle.sign(
      "HMAC",
      masterKey,
      AESGCMkey_pos
    ); 
    let AESGCMkey = await subtle.importKey(
      "raw",
      AESGCMkey_signature,
      {name: "AES-GCM",length: 256},
      false,
      ["encrypt", "decrypt"]
    );

    return new Keychain({}, salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey);
  // throw "Not Implemented!";
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    //affirm the integrity of the KVS
    if(trustedDataCheck !== undefined){
      let checksum = await subtle.digest("SHA-256", repr);
      if(byteArrayToString(checksum) !== trustedDataCheck){
        throw "Tampering is detected!";
      }
    }
    let contents = JSON.parse(repr);
    let salt = contents["salt"];
    let HMACkey_pos = contents["HMACkey_pos"];
    let HMACkey_signature = untypedToTypedArray(contents["HMACkey_signature"]);
    let AESGCMkey_pos = contents["AESGCMkey_pos"];
    let AESGCMkey_signature = untypedToTypedArray(contents["AESGCMkey_signature"]);

    //password authentication
    let rawKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    let masterKey = await subtle.deriveKey(
      {name:"PBKDF2", salt: salt, iterations: Keychain.PBKDF2_ITERATIONS, hash: "SHA-256"},
      rawKey,
      {name: "HMAC", hash: "SHA-256",length: 256},
      false,
      ["sign", "verify"]
    );
    
    let HMAC_verification = await subtle.verify(
      "HMAC",
      masterKey,
      HMACkey_signature,
      HMACkey_pos
    );
    
    if(HMAC_verification === false){
      throw "Password is incorrect!";
    }
    let HMACkey = await subtle.importKey(
      "raw",
      HMACkey_signature,
      {name: "HMAC", hash: "SHA-256"},
      false,
      ["sign"]
    );

    let AESGCM_verification = await subtle.verify(
      "HMAC",
      masterKey,
      AESGCMkey_signature,
      AESGCMkey_pos
    );
    if(AESGCM_verification === false){
      throw "Password is incorrect!";
    };

    let AESGCMkey = await subtle.importKey(
      "raw",
      AESGCMkey_signature,
      {name: "AES-GCM",length: 256},
      false,
      ["encrypt", "decrypt"]
    );
    return new Keychain(contents["kvs"], salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey);
    //throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  async dump() {
    if(this.ready === false){
      return null;
    }
    //console.log("dumping", this.secrets);
    let contents = this.secrets;
    //console.log(contents["HMACkey"]);
    contents["HMACkey_signature"] = bufferToUntypedArray(contents["HMACkey_signature"]);
    contents["AESGCMkey_signature"] = bufferToUntypedArray(contents["AESGCMkey_signature"]);
    let repr = JSON.stringify(contents);
    //console.log(repr);
    let checksum = await subtle.digest("SHA-256", repr);
    return [repr, byteArrayToString(checksum)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if(this.ready === false){
      throw "Keychain not initialized.";
    }
    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACkey,
      name
    );
    key = bufferToUntypedArray(key);
    let plaintext = null;
    if(this.secrets.kvs.hasOwnProperty(key)){
      let value = this.secrets.kvs[key];
      let iv = byteArrayToString(untypedToTypedArray(value[0]));
      let ciphertext = untypedToTypedArray(value[1]);
      plaintext = await subtle.decrypt(
        {name: "AES-GCM", iv: iv},
        this.secrets.AESGCMkey,
        ciphertext
      );
      plaintext = byteArrayToString(untypedToTypedArray(paddedArrayToRaw(bufferToUntypedArray(plaintext),Keychain.Padded_Password_length)));
    }
    return plaintext;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if(this.ready === false){
      throw "Keychain not initialized.";
    }

    //compute key for the domain name
    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACkey,
      name
    );
    key = bufferToUntypedArray(key);//for dump on disk

    //encrypt the value
    let iv = stringToByteArray(genRandomSalt(12));//iv datatype - byte array
    let ciphertext = await subtle.encrypt(
      {name: "AES-GCM", iv: iv},
      this.secrets.AESGCMkey,
      untypedToTypedArray(rawToPaddedArray(stringToByteArray(value), Keychain.Padded_Password_length))
    );//byte padding "100000..." to 80 byteus

    //update this entry in KVS
    this.secrets.kvs[key] = [bufferToUntypedArray(iv), bufferToUntypedArray(ciphertext)];//use an untyped array to serialize entries in the KVS
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if(this.ready === false){
      throw "Keychain not initialized.";
    }
    //compute key for the domain name
    let key = await subtle.sign(
      "HMAC",
      this.secrets.HMACkey,
      name
    );
    key = bufferToUntypedArray(key);
    
    //remove the entry from KVS
    if(this.secrets.kvs.hasOwnProperty(key)){
      delete this.secrets.kvs[key];
      return true;
    }
    return false;
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
  static get Padded_Password_length() { return 80; }
};

module.exports = {
  Keychain: Keychain
}
