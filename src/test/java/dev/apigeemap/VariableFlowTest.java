package dev.apigeemap;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.analysis.VariableFlow;
import dev.apigeemap.analysis.VariableFlow.Read;
import dev.apigeemap.analysis.VariableFlow.Source;
import dev.apigeemap.migration.Finding;
import dev.apigeemap.migration.MigrationReport;
import dev.apigeemap.migration.Migrator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VariableFlowTest {

    private static final Path ORDERS = Path.of("examples/orders-api");
    private static final Path SHARED_FLOWS = Path.of("examples/sharedflows");

    @TempDir
    Path tmp;

    @Test
    void linksEachReadToTheStepsThatSetItBefore() throws IOException {
        VariableFlow flow = VariableFlow.of(new BundleAnalyzer(SharedFlowRepository.scan(List.of(SHARED_FLOWS)))
                .analyze(BundleLocator.locate(ORDERS)));

        Read password = read(flow, "AM-Backend-Auth", "private.backend.password");
        assertEquals(Source.SET, password.source());
        assertEquals("KVM-Get-Config", password.producers().get(0).policy());
        assertTrue(flow.consumersOf("KVM-Get-Config").stream().anyMatch(r -> r.step().policy().equals("AM-Backend-Auth")));

        assertEquals(Source.SET, read(flow, "SC-Customer", "lookupcache.LC-Orders.cachehit").source(),
                "a condition reads what LookupCache sets under its own name");
        assertEquals(Source.BUILT_IN, read(flow, "Verify-API-Key", "request.header.x-api-key").source());
        assertTrue(flow.readsOf("SC-Customer").stream().noneMatch(r -> r.variable().name().equals("customerRequest")),
                "an empty ServiceCallout Request does without an earlier message");

        // FlowCallouts bring what their shared flow reads and writes
        Read debug = read(flow, "FC-Security", "security.debug");
        assertEquals(Source.UNSET, debug.source());
        assertEquals("sf-security › FC-Logging (condition)", debug.variable().via());
        assertTrue(flow.steps().stream().anyMatch(s -> s.policy().equals("FC-Security")
                && s.writes().stream().anyMatch(w -> w.name().equals("private.jwt.key"))));

        assertTrue(flow.steps().stream().anyMatch(s -> s.type().equals("RouteRule")
                && s.reads().stream().anyMatch(r -> r.name().equals("request.header.X-Legacy"))));
    }

    @Test
    void followsTheOrderApigeeRunsTheSteps() throws IOException {
        Path bundle = bundle();
        VariableFlow flow = VariableFlow.of(new BundleAnalyzer(SharedFlowRepository.empty()).analyze(bundle));

        Read early = read(flow, "JS-Early", "order.id");
        assertEquals(Source.SET_LATER, early.source());
        assertEquals("EV-Order", early.producers().get(0).policy());
        assertEquals(Source.SET, read(flow, "JS-Late", "order.id").source());
        assertEquals(Source.SET, read(flow, "AM-Fault", "order.id").source(), "fault rules see every variable");
        assertEquals(Source.SET, read(flow, "JS-Late", "request.header.x-trace").source(),
                "header names are case-insensitive");
        assertEquals("AM-Trace", read(flow, "JS-Late", "request.header.x-trace").producers().get(0).policy());

        // Each RouteRule target is its own path: what the legacy target sets is not set for the default one
        assertEquals(Source.SET, read(flow, "JS-Legacy-Response", "legacy.token").source());
        assertEquals(Source.UNSET, read(flow, "JS-Default-Response", "legacy.token").source());

        // After a step that may set any variable, an unset variable is unknown rather than unset
        assertEquals(Source.UNKNOWN, read(flow, "JS-After-Callout", "from.java").source());
    }

    @Test
    void tellsApigeeVariablesFromNamesThatOnlyLookLikeThem() throws IOException {
        VariableFlow flow = VariableFlow.of(new BundleAnalyzer(SharedFlowRepository.empty()).analyze(bundle()));

        Read typo = read(flow, "JS-Typos", "request.heder.x-trace");
        assertEquals(Source.UNSET, typo.source());
        assertEquals("Apigee sets no request.heder.* variable: request.header?", typo.note());
        assertEquals(Source.BUILT_IN, read(flow, "JS-Typos", "proxy.pathsuffix").source());

        // a policy's own variables are set once that policy has run, not by Apigee
        Read missing = read(flow, "JS-Typos", "lookupcache.LC-Gone.cachehit");
        assertEquals(Source.UNSET, missing.source());
        assertEquals("no policy named LC-Gone runs in this bundle", missing.note());
        Read quota = read(flow, "JS-Typos", "ratelimit.Q-Later.exceed.count");
        assertEquals(Source.SET_LATER, quota.source());
        assertEquals("Q-Later", quota.producers().get(0).policy());
    }

    @Test
    void reportsVariablesReadBeforeTheyAreSet() throws IOException {
        MigrationReport report = new Migrator().migrate(new BundleAnalyzer(SharedFlowRepository.empty())
                .analyze(bundle()), null);
        List<Finding> findings = report.findings().stream().filter(f -> f.rule().equals("DES-13"))
                .filter(f -> !f.location().startsWith("JS-Typos")).toList();
        assertEquals(1, findings.size(), findings.toString());
        assertEquals("JS-Early (ProxyEndpoint default › PreFlow › Request)", findings.get(0).location());
        assertEquals("Reads order.id (set by EV-Order) before the step that sets it runs", findings.get(0).message());
    }

    @Test
    void printsTheFlowOfOnePolicy() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = Main.run(new String[]{"variables", ORDERS.toString(), "-s", SHARED_FLOWS.toString(),
                "--policy", "KVM-Get-Config"}, new PrintStream(out), new PrintStream(new ByteArrayOutputStream()));
        assertEquals(0, code);
        String text = out.toString();
        assertTrue(text.contains("writes  private.backend.password"), text);
        assertTrue(text.matches("(?s).*Read by\\n  private\\.backend\\.password +AM-Backend-Auth .*"), text);

        out.reset();
        Main.run(new String[]{"variables", ORDERS.toString(), "-f", "json"}, new PrintStream(out),
                new PrintStream(new ByteArrayOutputStream()));
        assertTrue(out.toString().matches("(?s).*\"source\": \"SET\",\\s+\"producers\": \\[\\s+\"KVM-Get-Config \\(.*"),
                out.toString());
    }

    private static Read read(VariableFlow flow, String policy, String variable) {
        return flow.readsOf(policy).stream().filter(r -> r.variable().name().equals(variable)).findFirst()
                .orElseThrow(() -> new AssertionError(policy + " does not read " + variable));
    }

    /** A proxy with two targets, a fault rule, a step that reads too early and a Java callout. */
    private Path bundle() throws IOException {
        Path dir = tmp.resolve("flow-api/apiproxy");
        write(dir, "flow-api.xml", "<APIProxy name=\"flow-api\"/>");
        write(dir, "proxies/default.xml", """
                <ProxyEndpoint name="default">
                    <PreFlow>
                        <Request>
                            <Step><Name>JS-Early</Name></Step>
                            <Step><Name>AM-Trace</Name></Step>
                            <Step><Name>EV-Order</Name></Step>
                            <Step><Name>JS-Late</Name></Step>
                        </Request>
                    </PreFlow>
                    <FaultRules>
                        <FaultRule name="any"><Step><Name>AM-Fault</Name></Step></FaultRule>
                    </FaultRules>
                    <HTTPProxyConnection><BasePath>/flow</BasePath></HTTPProxyConnection>
                    <RouteRule name="legacy">
                        <Condition>request.header.X-Legacy = "true"</Condition>
                        <TargetEndpoint>legacy</TargetEndpoint>
                    </RouteRule>
                    <RouteRule name="default"><TargetEndpoint>default</TargetEndpoint></RouteRule>
                </ProxyEndpoint>
                """);
        write(dir, "targets/legacy.xml", """
                <TargetEndpoint name="legacy">
                    <PreFlow>
                        <Request>
                            <Step><Name>AM-Legacy-Token</Name></Step>
                            <Step><Name>JC-Anything</Name></Step>
                        </Request>
                        <Response>
                            <Step><Name>JS-Legacy-Response</Name></Step>
                            <Step><Name>JS-After-Callout</Name></Step>
                        </Response>
                    </PreFlow>
                    <HTTPTargetConnection><URL>https://legacy.example.com</URL></HTTPTargetConnection>
                </TargetEndpoint>
                """);
        write(dir, "targets/default.xml", """
                <TargetEndpoint name="default">
                    <PreFlow>
                        <Response>
                            <Step><Name>JS-Default-Response</Name></Step>
                            <Step><Name>JS-Typos</Name></Step>
                            <Step><Name>Q-Later</Name></Step>
                        </Response>
                    </PreFlow>
                    <HTTPTargetConnection><URL>https://api.example.com</URL></HTTPTargetConnection>
                </TargetEndpoint>
                """);
        script(dir, "JS-Early", "context.getVariable('order.id');");
        script(dir, "JS-Late", "context.getVariable('order.id'); context.getVariable('request.header.x-trace');");
        script(dir, "JS-After-Callout", "context.getVariable('from.java');");
        script(dir, "JS-Typos", "context.getVariable('request.heder.x-trace'); context.getVariable('proxy.pathsuffix');"
                + " context.getVariable('lookupcache.LC-Gone.cachehit');"
                + " context.getVariable('ratelimit.Q-Later.exceed.count');");
        script(dir, "JS-Legacy-Response", "context.getVariable('legacy.token');");
        script(dir, "JS-Default-Response", "context.getVariable('legacy.token');");
        write(dir, "policies/AM-Trace.xml", """
                <AssignMessage name="AM-Trace">
                    <Set><Headers><Header name="X-Trace">{messageid}</Header></Headers></Set>
                </AssignMessage>
                """);
        write(dir, "policies/EV-Order.xml", """
                <ExtractVariables name="EV-Order">
                    <VariablePrefix>order</VariablePrefix>
                    <URIPath><Pattern>/orders/{id}</Pattern></URIPath>
                </ExtractVariables>
                """);
        write(dir, "policies/AM-Fault.xml", """
                <AssignMessage name="AM-Fault">
                    <Set><Payload contentType="application/json">{"order":"{order.id}"}</Payload></Set>
                </AssignMessage>
                """);
        write(dir, "policies/AM-Legacy-Token.xml", """
                <AssignMessage name="AM-Legacy-Token">
                    <AssignVariable><Name>legacy.token</Name><Value>abc</Value></AssignVariable>
                </AssignMessage>
                """);
        write(dir, "policies/Q-Later.xml", """
                <Quota name="Q-Later"><Allow count="10"/><Interval>1</Interval><TimeUnit>minute</TimeUnit></Quota>
                """);
        write(dir, "policies/JC-Anything.xml", """
                <JavaCallout name="JC-Anything"><ClassName>com.example.Anything</ClassName></JavaCallout>
                """);
        return dir;
    }

    private static void script(Path dir, String policy, String code) throws IOException {
        String file = policy.toLowerCase() + ".js";
        write(dir, "policies/" + policy + ".xml", "<Javascript name=\"" + policy + "\"><ResourceURL>jsc://" + file
                + "</ResourceURL></Javascript>");
        write(dir, "resources/jsc/" + file, code);
    }

    private static void write(Path dir, String file, String content) throws IOException {
        Path path = dir.resolve(file);
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
    }
}
