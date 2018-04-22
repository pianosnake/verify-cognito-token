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

async function verifyToken(token, params) {
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

    if(!claims.iss.endsWith(params.userPoolId)) throw Error('iss claim does not match user pool ID');

    const now = Math.floor(new Date() / 1000);
    if (now > claims.exp) throw Error('Token is expired');
    
    if (params.appClientId && claims.aud && claims.aud !== params.appClientId) throw Error('Token was not issued for this audience');

    if(params.appClientId && claims.token_use === 'access') console.warn('WARNING! Access tokens do not have an audience');
    
    return true;

  } catch (e) {
    console.log(e);
    return false;
  }
}

function verify(params = {}){
  if(!params.userPoolId) throw Error('userPoolId param is required');
  if(!params.region) throw Error('region param is required');

  keysUrl = 'https://cognito-idp.' + params.region + '.amazonaws.com/' + params.userPoolId + '/.well-known/jwks.json';
  return token => verifyToken(token, params)
}

module.exports = verify;