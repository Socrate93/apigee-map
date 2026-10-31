package dev.apigeemap.simulation;

import dev.apigeemap.analysis.BundleAnalyzer;
import dev.apigeemap.analysis.BundleLocator;
import dev.apigeemap.analysis.SharedFlowRepository;
import dev.apigeemap.simulation.Simulation.Entry;
import dev.apigeemap.simulation.Simulation.Input;
import dev.apigeemap.simulation.Simulation.Result;
import dev.apigeemap.simulation.Simulation.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimulatorTest {

    private static final String ENDPOINT = """
            <ProxyEndpoint name="default">
                <PreFlow name="PreFlow">
                    <Request>
                        <Step><Name>VA-Key</Name></Step>
                        <Step><Name>EV-Id</Name></Step>
                        <Step>
                            <Name>RF-Admin</Name>
                            <Condition>request.header.x-role = "guest"</Condition>
                        </Step>
                    </Request>
                    <Response/>
                </PreFlow>
                <Flows>
                    <Flow name="never">
                        <Condition>request.verb = "DELETE"</Condition>
                        <Request><Step><Name>AM-Wrong</Name></Step></Request>
                    </Flow>
                    <Flow name="orders">
                        <Condition>proxy.pathsuffix MatchesPath "/orders/*"</Condition>
                        <Request><Step><Name>AM-Header</Name></Step></Request>
                        <Response><Step><Name>JS-Shape</Name></Step></Response>
                    </Flow>
                    <Flow name="also">
                        <Condition>proxy.pathsuffix MatchesPath "/orders/*"</Condition>
                        <Request><Step><Name>AM-Wrong</Name></Step></Request>
                    </Flow>
                </Flows>
                <PostFlow name="PostFlow"><Request/><Response/></PostFlow>
                <FaultRules>
                    <FaultRule name="first">
                        <Step><Name>AM-Wrong</Name></Step>
                        <Condition>fault.name = "Nothing"</Condition>
                    </FaultRule>
                    <FaultRule name="denied">
                        <Step><Name>AM-Denied</Name></Step>
                        <Condition>fault.name = "InvalidApiKey"</Condition>
                    </FaultRule>
                </FaultRules>
                <HTTPProxyConnection><BasePath>/v1</BasePath></HTTPProxyConnection>
                <RouteRule name="none">
                    <Condition>request.header.x-mock = "true"</Condition>
                </RouteRule>
                <RouteRule name="default"><TargetEndpoint>default</TargetEndpoint></RouteRule>
            </ProxyEndpoint>
            """;

    @TempDir
    Path tmp;

    private Result run(Input input) throws IOException {
        Path bundle = tmp.resolve("sim/apiproxy");
        write(bundle, "sim.xml", "<APIProxy name=\"sim\"/>");
        write(bundle, "proxies/default.xml", ENDPOINT);
        write(bundle, "targets/default.xml", """
                <TargetEndpoint name="default">
                    <HTTPTargetConnection><URL>https://example.com</URL></HTTPTargetConnection>
                </TargetEndpoint>
                """);
        write(bundle, "policies/VA-Key.xml", "<VerifyAPIKey name=\"VA-Key\"><APIKey ref=\"request.header.x-api-key\"/></VerifyAPIKey>");
        write(bundle, "policies/EV-Id.xml", """
                <ExtractVariables name="EV-Id">
                    <Source>request</Source>
                    <VariablePrefix>orders</VariablePrefix>
                    <URIPath><Pattern>/orders/{id}</Pattern></URIPath>
                    <JSONPayload><Variable name="total"><JSONPath>$.items[1].price</JSONPath></Variable></JSONPayload>
                </ExtractVariables>
                """);
        write(bundle, "policies/RF-Admin.xml", """
                <RaiseFault name="RF-Admin">
                    <FaultResponse><Set><Payload contentType="text/plain">no {request.header.x-role}</Payload><StatusCode>403</StatusCode></Set></FaultResponse>
                </RaiseFault>
                """);
        write(bundle, "policies/AM-Header.xml", """
                <AssignMessage name="AM-Header">
                    <AssignTo createNew="false" type="request"/>
                    <Set><Headers><Header name="x-order">{orders.id}</Header></Headers></Set>
                    <AssignVariable><Name>seen</Name><Template>id-{orders.id}</Template></AssignVariable>
                    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
                </AssignMessage>
                """);
        write(bundle, "policies/AM-Wrong.xml", "<AssignMessage name=\"AM-Wrong\"><AssignVariable><Name>wrong</Name><Value>1</Value></AssignVariable></AssignMessage>");
        write(bundle, "policies/AM-Denied.xml", """
                <AssignMessage name="AM-Denied">
                    <AssignTo createNew="false" type="response"/>
                    <Set><Payload contentType="application/json">{"error":"key"}</Payload><StatusCode>401</StatusCode></Set>
                </AssignMessage>
                """);
        write(bundle, "policies/JS-Shape.xml", "<Javascript name=\"JS-Shape\"><ResourceURL>jsc://shape.js</ResourceURL></Javascript>");
        write(bundle, "resources/jsc/shape.js", """
                var id = context.getVariable("orders.id");
                context.setVariable("shaped", "order " + id);
                context.proxyResponse.content = JSON.stringify({id: id, was: context.getVariable("response.content")});
                """);
        var report = new BundleAnalyzer(SharedFlowRepository.empty()).analyze(BundleLocator.locate(tmp.resolve("sim")));
        return Simulator.run(report, input);
    }

    private static void write(Path bundle, String path, String text) throws IOException {
        Path file = bundle.resolve(path);
        Files.createDirectories(file.getParent());
        Files.writeString(file, text);
    }

    private static Input call(String verb, String path, Map<String, String> headers, String body, Set<String> failing) {
        return new Input(verb, path, headers, body, "200", "backend", Map.of(), failing);
    }

    private static Entry entry(Result result, String name) {
        return result.entries().stream().filter(e -> e.name().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void runsTheFirstMatchingFlowAndTheTarget() throws Exception {
        Result result = run(call("GET", "/v1/orders/12?x=1", Map.of("x-api-key", "k"), "{\"items\":[{},{\"price\":5}]}", Set.of()));

        assertNull(result.fault());
        assertEquals("200", result.response().status());
        assertEquals(Status.ASSUMED, entry(result, "VA-Key").status());
        assertEquals(Status.SKIPPED, entry(result, "RF-Admin").status());
        assertEquals(Status.SKIPPED, entry(result, "never").status());
        assertEquals(Status.RAN, entry(result, "orders").status());
        assertTrue(result.entries().stream().noneMatch(e -> e.name().equals("also")), "only the first match runs");
        assertTrue(result.entries().stream().noneMatch(e -> e.name().equals("AM-Wrong")));
        assertTrue(entry(result, "EV-Id").changes().stream().anyMatch(c -> c.name().equals("orders.id") && c.after().equals("12")));
        assertTrue(entry(result, "EV-Id").changes().stream().anyMatch(c -> c.name().equals("orders.total") && c.after().equals("5")));
        assertTrue(entry(result, "AM-Header").changes().stream().anyMatch(c -> c.name().equals("request.header.x-order") && c.after().equals("12")));
        assertTrue(entry(result, "AM-Header").changes().stream().anyMatch(c -> c.name().equals("seen") && c.after().equals("id-12")));
        assertEquals("{\"id\":\"12\",\"was\":\"backend\"}", result.response().body());
    }

    @Test
    void takesTheFirstRouteThatMatches() throws Exception {
        Result result = run(call("GET", "/v1/other", Map.of("x-mock", "true"), null, Set.of()));

        assertEquals(Status.RAN, entry(result, "none").status());
        assertTrue(result.entries().stream().noneMatch(e -> e.name().equals("default")));
        assertNull(result.response().body());
    }

    @Test
    void aRaisedFaultStopsTheFlowWithItsResponse() throws Exception {
        Result result = run(call("GET", "/v1/orders/12", Map.of("x-role", "guest"), null, Set.of()));

        assertEquals("RaiseFault", result.fault());
        assertEquals("403", result.response().status());
        assertEquals("no guest", result.response().body());
        assertEquals("text/plain", result.response().headers().get("Content-Type"));
        assertEquals(Status.FAILED, entry(result, "RF-Admin").status());
        assertTrue(result.entries().stream().noneMatch(e -> e.name().equals("AM-Header")));
    }

    @Test
    void aPolicyAskedToFailRunsTheMatchingFaultRule() throws Exception {
        Result result = run(call("GET", "/v1/orders/12", Map.of(), null, Set.of("VA-Key")));

        assertEquals("InvalidApiKey", result.fault());
        assertEquals(Status.FAILED, entry(result, "VA-Key").status());
        assertEquals(Status.RAN, entry(result, "AM-Denied").status());
        assertTrue(result.entries().stream().noneMatch(e -> e.name().equals("AM-Wrong")));
        assertEquals("401", result.response().status());
        assertEquals("{\"error\":\"key\"}", result.response().body());
    }

    @Test
    void anErrorFromTheTargetGoesToTheFaultRules() throws Exception {
        Result result = run(new Input("GET", "/v1/orders/12", Map.of(), null, "503", "down", Map.of(), Set.of()));

        assertEquals("ErrorResponseCode", result.fault());
        assertEquals("503", result.response().status());
        assertEquals("down", result.response().body());
        assertFalse(result.entries().stream().anyMatch(e -> e.name().equals("JS-Shape")));
    }

    @Test
    void conditionalFlowsSeeWhatThePreFlowSets() throws Exception {
        Result result = run(call("DELETE", "/v1/orders/12", Map.of(), null, Set.of()));

        assertEquals(Status.RAN, entry(result, "never").status());
        int preFlow = result.entries().indexOf(entry(result, "EV-Id"));
        assertTrue(preFlow < result.entries().indexOf(entry(result, "never")));
    }

    @Test
    void aPathOutsideTheBasePathIsReported() throws Exception {
        assertTrue(run(call("GET", "/elsewhere", Map.of(), null, Set.of())).warnings().get(0).contains("no base path"));
    }

    @Test
    void playsTheExampleWithItsSharedFlows() throws Exception {
        Path examples = Path.of("examples").toAbsolutePath();
        var report = new BundleAnalyzer(SharedFlowRepository.scan(List.of(examples.resolve("sharedflows"))))
                .analyze(BundleLocator.locate(examples.resolve("orders-api")));

        Result result = Simulator.run(report, new Input("GET", "/v1/orders/42", Map.of("x-api-key", "k"), null, "200",
                "{}", Map.of("private.backend.password", "secret"), Set.of()));

        assertTrue(result.entries().stream().anyMatch(e -> !e.bundle().equals("orders-api")), "runs inside shared flows");
        assertEquals(Status.RAN, entry(result, "getOrder").status());
        assertTrue(result.entries().stream().flatMap(e -> e.changes().stream())
                .noneMatch(c -> "secret".equals(c.after())), "private values stay out of the result: " + result);
    }
}
