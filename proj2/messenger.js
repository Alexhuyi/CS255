'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/
const MAX_SKIP = 1000;
//external functions listed in https://signal.org/docs/specifications/doubleratchet/#introduction
async function GENERATE_DH(){
  return await generateEG();
}

async function DH(dh_pair,du_pub){
  return await computeDH(dh_pair.sec,du_pub);
}

async function KDF_RK(rk, dh_out){
  let [hkdfOut1,hkdfOut2] =  await HKDF(rk, dh_out, "rachet-str");
  return [hkdfOut1, hkdfOut2];
}

async function KDF_CK(ck){
  let CKnew = await HMACtoHMACKey(ck, "chainkey");
  let mk = await HMACtoAESKey(ck, "messagekey");
  let mkBuf = await HMACtoAESKey(ck, "messagekey",true);
  return [CKnew, mk, mkBuf];
}

async function ENCRYPT(mk, plaintext, iv, associated_data = ''){
  // console.log(typeof(mk), typeof(plaintext), typeof(iv), typeof(associated_data));
  return encryptWithGCM(mk, plaintext, iv, associated_data);
}

async function DECRYPT(mk, ciphertext, iv, associated_data = ''){
  return decryptWithGCM(mk, ciphertext, iv, associated_data);
}

async function HEADER(dh_pair, pn, n, mkBuf, iv, govPublicKey){
  const dhGov = await GENERATE_DH();
  const kGov = await DH(dhGov, govPublicKey);
  const aesKeyGov = await HMACtoAESKey(kGov, govEncryptionDataStr);
  const ivGov = genRandomSalt();
  const cGov = await ENCRYPT(aesKeyGov, mkBuf, ivGov);
  const header = {
    pub: dh_pair.pub,
    previous_chain_length: pn,
    message_number:n,
    receiverIV:iv,
    vGov: dhGov.pub,
    ivGov:ivGov,
    cGov
  };
  return header
}

async function TrySkippedMessageKeys(state, header, ciphertext){
  let key = JSON.stringify([header.pub,header.message_number]);
  if(state.MKSKIPPED[key] !== undefined){
    let mk = state.MKSKIPPED[key];
    delete state.MKSKIPPED[key];
    return byteArrayToString(await DECRYPT(mk, ciphertext, header.receiverIV, JSON.stringify(header)));
  } else{
    return null;
  }
}

async function SkipMessageKeys(state,until){
  if( state.Nr + MAX_SKIP < until){
    throw("Too many skipped messages!");
  }
  if(state.CKr !== null){
    while(state.Nr < until){
      let mk, mkBuf;
      [state.CKr, mk, mkBuf] = await KDF_CK(state.CKr);
      state.MKSKIPPED[JSON.stringify([state.DHr, state.Nr])] = mk;
      state.Nr++;
    }
  }
}

async function DHRatchet(state, header){
  state.PN = state.Ns;
  state.Ns = 0;
  state.Nr = 0;
  state.DHr = header.pub;
  let dh_out = await DH(state.DHs, state.DHr);
  let RK,CKr,CKs;
  [RK, CKr] = await KDF_RK(state.RK, dh_out);
  state.RK = RK;
  state.CKr = CKr;
  state.DHs = await GENERATE_DH();
  dh_out = await DH(state.DHs, state.DHr);
  [RK,CKs] = await KDF_RK(state.RK, dh_out);
  state.RK = RK;
  state.CKs = CKs;
}

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    //throw ('not implemented!')
    const {pub, sec} = await GENERATE_DH();
    this.EGKeyPair = {pub, sec};
    const certificate = {username, pub};
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    const verify = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (verify) {
      this.certs[certificate.username] = certificate;
    } else {
      throw ('Invalid certificate!');
     }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    const theirCert = this.certs[name];
    const theirPub = theirCert.pub;
    const SK = await DH(this.EGKeyPair, theirPub);
    if(!this.conns[name]) {
      //Alice - rachet init
      const DHs = await GENERATE_DH();
      const DHr = theirPub;
      const DH_out = await DH(DHs, DHr);
      const [RK, CKs] = await KDF_RK(SK, DH_out);
      this.conns[name] = {
        DHs, 
        DHr, 
        RK, 
        CKs, 
        CKr:null, 
        Ns:0, 
        Nr:0, 
        PN:0, 
        MKSKIPPED:{}
      };
    }
    //ALice - sending chain rachet step, KDF_CF
    const state = this.conns[name];
    if(state.CKs === null){
      const DHs = await GENERATE_DH();
      const DHr = theirPub;
      const DH_out = await DH(DHs, DHr);
      const [RK, CKs] = await KDF_RK(SK, DH_out); 
      state.DHs = DHs;
      state.CKs = CKs;
      state.RK = RK;
    }
    const [CKs_new,mk, mkBuf] = await KDF_CK(state.CKs);
    state.CKs = CKs_new;

    //create a header
    const iv_message = genRandomSalt();
    const header = await HEADER(state.DHs, state.PN, state.Ns,  mkBuf, iv_message, this.govPublicKey);
    state.Ns += 1;
    
    const ciphertext = await ENCRYPT(mk, plaintext, iv_message, JSON.stringify(header));
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    if(!this.conns[name]){
      const theirCert = this.certs[name];
      const theirPub = theirCert.pub;
      const SK = await DH(this.EGKeyPair, theirPub);
      const DHs = this.EGKeyPair;
      const DH_out = await DH(DHs, header.pub);
      const [RK, CKr] = await KDF_RK(SK, DH_out);
      this.conns[name] = {
        DHs,
        DHr:header.pub,
        RK,
        CKs:null,
        CKr,
        Ns:0,
        Nr:0,
        PN:0,
        MKSKIPPED:{}
      }
    }
    const state = this.conns[name];
    if(state.CKr === null){
      const theirCert = this.certs[name];
      const theirPub = theirCert.pub;
      const SK = await DH(this.EGKeyPair, theirPub);
      const DHs = this.EGKeyPair;
      const DH_out = await DH(DHs, header.pub);
      const [RK, CKr] = await KDF_RK(SK, DH_out);
      state.CKr = CKr;
      state.RK = RK;
      state.DHr = header.pub;
    }
    let plaintext = await TrySkippedMessageKeys(state, header, ciphertext);
    if(plaintext !== null){
      return plaintext;
    }
    if (header.pub !== state.DHr){
      await SkipMessageKeys(state, header.previous_chain_length);
      await DHRatchet(state, header);
    }
    await SkipMessageKeys(state, header.message_number);
    
    const [CKr_new, mk, mkBuf] = await KDF_CK(state.CKr);
    state.CKr = CKr_new;
    state.Nr++;

    try{
      plaintext = byteArrayToString(await DECRYPT(mk, ciphertext, header.receiverIV, JSON.stringify(header)));
      return plaintext;
    } catch(err){
      // console.log(err);
      throw ('Tampering detected!');
    }
  }
};

module.exports = {
  MessengerClient
}
