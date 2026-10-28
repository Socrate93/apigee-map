/* Copy of audit.js kept for the delete flow */
var host   = context.getVariable("virtualhost.name");
var event  = { order: context.getVariable("orderId"), host: host, at: Date.now() };   // audit payload
httpClient.send(new Request("http://localhost:7000/audit", "POST", {"Content-Type": "application/json"},
        JSON.stringify(event)));
