// The clients only see this proxy: its endpoints replace those of the IdP in the discovery document.
var issuer = context.getVariable('oauth.issuer');
var metadata = JSON.parse(context.getVariable('response.content'));

metadata.issuer = issuer;
metadata.authorization_endpoint = issuer + '/authorize';
metadata.token_endpoint = issuer + '/token';
metadata.introspection_endpoint = issuer + '/introspect';
metadata.revocation_endpoint = issuer + '/revoke';
metadata.userinfo_endpoint = issuer + '/userinfo';
metadata.jwks_uri = issuer + '/jwks';
metadata.grant_types_supported = ['authorization_code', 'client_credentials', 'password', 'refresh_token',
  'urn:ietf:params:oauth:grant-type:saml2-bearer'];
metadata.code_challenge_methods_supported = ['S256'];

context.setVariable('response.content', JSON.stringify(metadata));
