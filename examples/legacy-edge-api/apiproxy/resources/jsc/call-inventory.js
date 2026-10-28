// Checks stock before forwarding the order
var apiKey = "a1b2c3d4e5f6";
var req = new Request("https://inventory.example.com/v2/stock", "GET", {"x-api-key": apiKey});
var exchange = httpClient.send(req);
exchange.waitForComplete();
context.setVariable("inventory.status", exchange.getResponse().status);
