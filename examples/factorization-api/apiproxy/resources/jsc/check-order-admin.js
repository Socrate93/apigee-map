// Rejects orders (admin) that are closed or too large
var ctx = context;
var id = ctx.getVariable("orderId");
var status = ctx.getVariable("order.status");
var total = parseFloat(context.getVariable("order.total") || "0");
if (status === "CLOSED" || total > 50000) {
    context.setVariable("check.rejected", "true");
    context.setVariable("check.reason", "order " + id + " cannot change");
}
