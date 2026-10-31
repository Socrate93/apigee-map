package dev.apigeemap.simulation;

import org.mozilla.javascript.BaseFunction;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ContextFactory;
import org.mozilla.javascript.RhinoException;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;

import java.util.List;
import java.util.function.BiFunction;

/** Runs the JavaScript of a policy against the flow variables, with no access to the machine. */
final class Scripts {

    /** A script stops after this many instructions, so that a loop cannot hang the check. */
    private static final int MAX_INSTRUCTIONS = 50_000_000;
    private static final int INSTRUCTIONS_PER_CHECK = 100_000;

    private static final class Limit extends ContextFactory {

        private static final class Counted extends Context {
            private long instructions;

            Counted(ContextFactory factory) {
                super(factory);
            }
        }

        @Override
        protected Context makeContext() {
            Counted context = new Counted(this);
            context.setInstructionObserverThreshold(INSTRUCTIONS_PER_CHECK);
            return context;
        }

        @Override
        protected void observeInstructionCount(Context context, int count) {
            Counted counted = (Counted) context;
            counted.instructions += count;
            if (counted.instructions > MAX_INSTRUCTIONS) throw new Error("The script runs too long");
        }
    }

    private static final Limit LIMIT = new Limit();

    /** {@code context.proxyRequest} and the like, as far as they read and write flow variables. */
    private static final String MESSAGES = """
            function __message(name) {
              return {
                get content() { return context.getVariable(name + '.content'); },
                set content(value) { context.setVariable(name + '.content', value); },
                get method() { return context.getVariable(name + '.verb'); },
                set method(value) { context.setVariable(name + '.verb', value); },
                get status() { return context.getVariable(name + '.status.code'); },
                set status(value) { context.setVariable(name + '.status.code', value); }
              };
            }
            context.proxyRequest = context.targetRequest = __message('request');
            context.proxyResponse = context.targetResponse = __message('response');
            var request = context.proxyRequest, response = context.proxyResponse;
            """;

    private Scripts() {
    }

    /**
     * @param sources the scripts, the last being the one the policy runs
     * @return what stopped it, or null
     */
    static String run(List<String> sources, Exchange exchange) {
        Context context = LIMIT.enterContext();
        try {
            context.setOptimizationLevel(-1);
            context.setLanguageVersion(Context.VERSION_ES6);
            ScriptableObject scope = context.initSafeStandardObjects();
            Scriptable host = context.newObject(scope);
            ScriptableObject.putProperty(scope, "context", host);
            function(host, "getVariable", (name, value) -> exchange.get(name));
            function(host, "setVariable", (name, value) -> {
                exchange.set(name, value);
                return null;
            });
            function(host, "removeVariable", (name, value) -> {
                exchange.set(name, null);
                return null;
            });
            function(scope, "print", (name, value) -> null);
            context.evaluateString(scope, MESSAGES, "context", 1, null);
            for (String source : sources) context.evaluateString(scope, source, "script", 1, null);
            return null;
        } catch (RhinoException e) {
            return e.getMessage();
        } catch (Error e) {
            if (e.getClass() == Error.class) return e.getMessage();
            throw e;
        } finally {
            Context.exit();
        }
    }

    private static void function(Scriptable owner, String name, BiFunction<String, String, String> body) {
        ScriptableObject.putProperty(owner, name, new BaseFunction() {
            @Override
            public Object call(Context context, Scriptable scope, Scriptable thisObject, Object[] args) {
                String first = text(args, 0);
                String result = body.apply(first, text(args, 1));
                return result;
            }
        });
    }

    private static String text(Object[] args, int index) {
        if (index >= args.length || args[index] == null || args[index] == Undefined.instance) return null;
        return Context.toString(args[index]);
    }
}
