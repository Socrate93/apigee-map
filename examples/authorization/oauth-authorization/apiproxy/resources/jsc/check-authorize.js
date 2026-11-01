// Checks the authorize request and prepares the session kept while the user logs in at the IdP.
function randomId() {
  var hash = crypto.getSHA256();
  hash.update(context.getVariable('messageid') + Math.random());
  return hash.digest();
}

var redirectUri = context.getVariable('authorize.redirect_uri');
var challenge = context.getVariable('authorize.code_challenge');
var error = null;

if (context.getVariable('authorize.response_type') !== 'code') error = 'Only response_type=code is supported';
else if (redirectUri !== context.getVariable('app.callback_url')) error = 'The redirect_uri is not registered';
else if (!challenge) error = 'code_challenge is required';
else if (context.getVariable('authorize.code_challenge_method') !== 'S256') error = 'Only S256 is supported';

if (error) {
  context.setVariable('authorize.error', error);
} else {
  var state = randomId();
  var nonce = context.getVariable('authorize.nonce') || randomId();
  context.setVariable('session.broker_state', state);
  context.setVariable('session.nonce', nonce);
  context.setVariable('session.json', JSON.stringify({
    client_id: context.getVariable('verifyapikey.VA-Authorize-Client.client_id'),
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: context.getVariable('authorize.scope'),
    state: context.getVariable('authorize.state'),
    nonce: nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  }));
}
