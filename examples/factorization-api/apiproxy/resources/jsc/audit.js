// Sends an audit event without waiting for the answer
var host = context.getVariable("virtualhost.name");
var event = { order: context.getVariable("orderId"), host: host, at: Date.now() };
httpClient.send(new Request("http://localhost:7000/audit", "POST", {"Content-Type": "application/json"},
        JSON.stringify(event)));
