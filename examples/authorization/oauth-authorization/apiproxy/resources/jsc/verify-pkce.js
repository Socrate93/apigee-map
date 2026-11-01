// RFC 7636: BASE64URL(SHA256(code_verifier)) must be the challenge kept with the authorization code.
var verifier = context.getVariable('token.code_verifier') || '';
var hash = crypto.getSHA256();
hash.update(verifier);
var computed = hash.digest64().replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

context.setVariable('pkce.valid',
  String(computed === context.getVariable('oauthv2authcode.GOI-Code.code_challenge')));
