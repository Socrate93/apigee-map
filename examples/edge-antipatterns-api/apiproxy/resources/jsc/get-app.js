// Looks up the calling app to read its custom attributes
var org = context.getVariable("organization.name");
var url = "https://api.enterprise.apigee.com/v1/organizations/" + org + "/apps/" + context.getVariable("client_id");
httpClient.get(url);
