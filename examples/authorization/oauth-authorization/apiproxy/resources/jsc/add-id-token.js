// Adds the ID token to the answer of the OAuthV2 policy.
var answer = JSON.parse(context.getVariable('response.content'));
answer.id_token = context.getVariable('token.id_token');
context.setVariable('response.content', JSON.stringify(answer));
