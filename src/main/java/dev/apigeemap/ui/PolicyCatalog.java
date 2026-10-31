package dev.apigeemap.ui;

import java.util.List;

/** The policies the Editor page can add to a proxy. In a template, {@code {{name}}} stands for the name of the policy. */
final class PolicyCatalog {

    private static final String ATTRIBUTES = "async=\"false\" continueOnError=\"false\" enabled=\"true\" name=\"{{name}}\"";

    /**
     * @param prefix what the name of this kind of policy starts with
     * @param script text of the {@code resources/jsc/{{name}}.js} file it runs; null when it has none
     */
    record Entry(String type, String group, String prefix, String summary, String template, String script) {

        Entry(String type, String group, String prefix, String summary, String body) {
            this(type, group, prefix, summary, xml(type, body), null);
        }
    }

    static final List<Entry> ENTRIES = List.of(
            new Entry("VerifyAPIKey", "Security", "VA", "Checks the API key of the request", """
                        <APIKey ref="request.header.x-api-key"/>
                    """),
            new Entry("OAuthV2", "Security", "OA", "Checks an OAuth access token", """
                        <Operation>VerifyAccessToken</Operation>
                    """),
            new Entry("VerifyJWT", "Security", "VJ", "Checks a signed JWT", """
                        <Algorithm>RS256</Algorithm>
                        <Source>request.header.authorization</Source>
                        <PublicKey>
                            <JWKS ref="jwks.content"/>
                        </PublicKey>
                    """),
            new Entry("BasicAuthentication", "Security", "BA", "Encodes or decodes HTTP Basic credentials", """
                        <Operation>Decode</Operation>
                        <IgnoreUnresolvedVariables>false</IgnoreUnresolvedVariables>
                        <User ref="credentials.username"/>
                        <Password ref="credentials.password"/>
                        <Source>request.header.Authorization</Source>
                    """),
            new Entry("JSONThreatProtection", "Security", "JTP", "Limits the structure of JSON payloads", """
                        <ArrayElementCount>100</ArrayElementCount>
                        <ContainerDepth>10</ContainerDepth>
                        <ObjectEntryCount>100</ObjectEntryCount>
                        <ObjectEntryNameLength>64</ObjectEntryNameLength>
                        <Source>request</Source>
                        <StringValueLength>4096</StringValueLength>
                    """),
            new Entry("XMLThreatProtection", "Security", "XTP", "Limits the structure of XML payloads", """
                        <NameLimits>
                            <Element>64</Element>
                            <Attribute>64</Attribute>
                        </NameLimits>
                        <Source>request</Source>
                        <StructureLimits>
                            <NodeDepth>10</NodeDepth>
                            <ChildCount>100</ChildCount>
                        </StructureLimits>
                    """),
            new Entry("RegularExpressionProtection", "Security", "REP", "Rejects requests matching patterns", """
                        <Source>request</Source>
                        <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
                        <QueryParam name="q">
                            <Pattern>[\\s]*(?i)((delete)|(exec)|(drop\\s*table))</Pattern>
                        </QueryParam>
                    """),
            new Entry("AccessControl", "Security", "AC", "Allows or denies client addresses", """
                        <IPRules noRuleMatchAction="ALLOW">
                            <MatchRule action="DENY">
                                <SourceAddress mask="32">192.0.2.1</SourceAddress>
                            </MatchRule>
                        </IPRules>
                    """),
            new Entry("Quota", "Traffic", "Q", "Limits the requests per period", """
                        <Allow count="1000"/>
                        <Interval>1</Interval>
                        <TimeUnit>hour</TimeUnit>
                        <Identifier ref="client_id"/>
                        <Distributed>true</Distributed>
                        <Synchronous>false</Synchronous>
                    """),
            new Entry("SpikeArrest", "Traffic", "SA", "Smooths traffic peaks", """
                        <Rate>100ps</Rate>
                    """),
            new Entry("ResponseCache", "Traffic", "RC", "Caches whole responses", """
                        <CacheKey>
                            <KeyFragment ref="request.uri"/>
                        </CacheKey>
                        <ExpirySettings>
                            <TimeoutInSec>300</TimeoutInSec>
                        </ExpirySettings>
                    """),
            new Entry("LookupCache", "Traffic", "LC", "Reads a value from the cache", """
                        <CacheKey>
                            <KeyFragment ref="request.uri"/>
                        </CacheKey>
                        <Scope>Exclusive</Scope>
                        <AssignTo>cached.value</AssignTo>
                    """),
            new Entry("PopulateCache", "Traffic", "PC", "Writes a value to the cache", """
                        <CacheKey>
                            <KeyFragment ref="request.uri"/>
                        </CacheKey>
                        <Scope>Exclusive</Scope>
                        <ExpirySettings>
                            <TimeoutInSec>300</TimeoutInSec>
                        </ExpirySettings>
                        <Source>response.content</Source>
                    """),
            new Entry("AssignMessage", "Mediation", "AM", "Changes a message or sets variables", """
                        <AssignTo createNew="false" transport="http" type="request"/>
                        <Set>
                            <Headers>
                                <Header name="x-example">value</Header>
                            </Headers>
                        </Set>
                        <IgnoreUnresolvedVariables>false</IgnoreUnresolvedVariables>
                    """),
            new Entry("ExtractVariables", "Mediation", "EV", "Reads variables from a message", """
                        <Source>request</Source>
                        <VariablePrefix>extracted</VariablePrefix>
                        <JSONPayload>
                            <Variable name="id">
                                <JSONPath>$.id</JSONPath>
                            </Variable>
                        </JSONPayload>
                        <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
                    """),
            new Entry("JSONToXML", "Mediation", "J2X", "Converts a JSON payload to XML", """
                        <Options>
                            <NullValue>NULL</NullValue>
                        </Options>
                        <OutputVariable>request</OutputVariable>
                        <Source>request</Source>
                    """),
            new Entry("XMLToJSON", "Mediation", "X2J", "Converts an XML payload to JSON", """
                        <Options>
                            <RecognizeNumber>true</RecognizeNumber>
                            <RecognizeBoolean>true</RecognizeBoolean>
                        </Options>
                        <OutputVariable>response</OutputVariable>
                        <Source>response</Source>
                    """),
            new Entry("RaiseFault", "Mediation", "RF", "Stops the flow and answers an error", """
                        <FaultResponse>
                            <Set>
                                <Payload contentType="application/json">{"error":"bad_request"}</Payload>
                                <StatusCode>400</StatusCode>
                                <ReasonPhrase>Bad Request</ReasonPhrase>
                            </Set>
                        </FaultResponse>
                        <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
                    """),
            new Entry("Javascript", "Mediation", "JS", "Runs a script", xml("Javascript", """
                        <ResourceURL>jsc://{{name}}.js</ResourceURL>
                    """).replace(" enabled=", " timeLimit=\"200\" enabled="), """
                    var path = context.getVariable("proxy.pathsuffix");
                    context.setVariable("example.path", path);
                    """),
            new Entry("ServiceCallout", "Extension", "SC", "Calls another service", """
                        <Request variable="calloutRequest">
                            <Set>
                                <Verb>GET</Verb>
                            </Set>
                        </Request>
                        <Response>calloutResponse</Response>
                        <Timeout>3000</Timeout>
                        <HTTPTargetConnection>
                            <LoadBalancer>
                                <Server name="example-server"/>
                            </LoadBalancer>
                            <Path>/</Path>
                        </HTTPTargetConnection>
                    """),
            new Entry("FlowCallout", "Extension", "FC", "Runs a shared flow", """
                        <SharedFlowBundle>example-shared-flow</SharedFlowBundle>
                    """),
            new Entry("KeyValueMapOperations", "Extension", "KVM", "Reads from a key value map",
                    xml("KeyValueMapOperations", """
                        <Scope>environment</Scope>
                        <ExpiryTimeInSecs>300</ExpiryTimeInSecs>
                        <Get assignTo="example.value">
                            <Key>
                                <Parameter>example-key</Parameter>
                            </Key>
                        </Get>
                    """).replace(" name=", " mapIdentifier=\"example-map\" name="), null),
            new Entry("MessageLogging", "Extension", "ML", "Writes a log line", """
                        <Syslog>
                            <Message>{messageid} {response.status.code}</Message>
                            <Host>logs.example.com</Host>
                            <Port>6514</Port>
                            <Protocol>TCP</Protocol>
                            <SSLInfo>
                                <Enabled>true</Enabled>
                            </SSLInfo>
                        </Syslog>
                    """));

    private PolicyCatalog() {
    }

    private static String xml(String type, String body) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<" + type + " " + ATTRIBUTES + ">\n"
                + "    <DisplayName>{{name}}</DisplayName>\n" + body + "</" + type + ">\n";
    }
}
