// The result of a client assertion comes from VerifyJWT, which stops the flow when it fails.
var typed = context.getVariable('private.client.secret') || '';
var expected = context.getVariable('private.app.consumer_secret') || '';
var different = typed.length ^ expected.length;
for (var i = 0; i < typed.length && i < expected.length; i++) {
  different |= typed.charCodeAt(i) ^ expected.charCodeAt(i);
}
context.setVariable('client.authenticated', String(different === 0 && expected.length > 0));
