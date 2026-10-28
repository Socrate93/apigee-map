var order = JSON.parse(context.getVariable('response.content'));
context.setVariable('response.content', JSON.stringify(formatOrder(order)));
