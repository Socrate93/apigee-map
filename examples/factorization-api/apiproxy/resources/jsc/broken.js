var body = JSON.parse(context.getVariable("request.content"));
if (body.items.length > 100 {
    context.setVariable("check.rejected", "true");
}
