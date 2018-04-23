const fetch = require('node-fetch');
const jose = require('node-jose');

let publicKeys, keysUrl; 

async function fetchKeys(){
  const publicKeysResponse = await fetch(keysUrl);
  const responseJson = await publicKeysResponse.json();
  return responseJson.keys;
}

//remember the keys for subsequent calls
async function getPublicKeys() {
  if(!publicKeys){
    publicKeys = fetchKeys();
  }
  return publicKeys; 
}

class Verifier{
  constructor(params){
    if(!params.userPoolId) throw Error('userPoolId param is required');
    if(!params.region) throw Error('region param is required');

    this.userPoolId = params.userPoolId;
    this.region = params.region;
    this.appClientId = params.appClientId;

    keysUrl = 'https://cognito-idp.' + this.region + '.amazonaws.com/' + this.userPoolId + '/.well-known/jwks.json';
  }

  async verify(token) {
    try {
      const sections = token.split('.');
      const header = JSON.parse(jose.util.base64url.decode(sections[0]));
      const kid = header.kid;
  
      const publicKeys = await getPublicKeys();
      
      const myPublicKey = publicKeys.find(k => k.kid === kid);
  
      if (!myPublicKey) throw Error('Public key not found at ' + keysUrl);
  
      const joseKey = await jose.JWK.asKey(myPublicKey);
  
      const verifiedToken = await jose.JWS.createVerify(joseKey).verify(token);
  
      const claims = JSON.parse(verifiedToken.payload);
  
      if(!claims.iss.endsWith(this.userPoolId)) throw Error('iss claim does not match user pool ID');
  
      const now = Math.floor(new Date() / 1000);
      if (now > claims.exp) throw Error('Token is expired');
      
      if (this.appClientId && claims.aud && claims.aud !== this.appClientId) throw Error('Token was not issued for this audience');
  
      if(this.appClientId && claims.token_use === 'access') console.warn('WARNING! Access tokens do not have an audience');
      
      return true;
  
    } catch (e) {
      console.log(e);
      return false;
    }
  }

  forgetPublicKeys(){
    publicKeys = null;
  }
}

module.exports = Verifier;