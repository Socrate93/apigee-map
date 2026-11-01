// Only an origin of the list gets the CORS headers.
var origin = context.getVariable('request.header.Origin');
var allowed = (context.getVariable('cors.allowed') || '').split(',');
if (origin && allowed.indexOf(origin) >= 0) context.setVariable('cors.origin', origin);
