# apigee-map

Maps the dependencies of an Apigee **OPDK** **API proxy** or **shared flow** from its local bundle (an `apiproxy/` /
`sharedflowbundle/` folder or an exported zip), and prepares its migration to Apigee hybrid. No call is made to the
Management API.

## Build

```bash
JAVA_HOME=~/Library/Java/JavaVirtualMachines/openjdk-21.0.2/Contents/Home mvn package
```

Outside the corporate VPN, pass an empty `settings.xml` (`-s empty-settings.xml`) to resolve from Maven Central.

External dependencies (Maven Central): **Mozilla Rhino** (`org.mozilla:rhino`), Apigee's JavaScript engine, used to
analyze the scripts of `Javascript` policies, and **JGit** (`org.eclipse.jgit`, with `slf4j-nop` to silence its
logs) for the history of bundles changed in place. They are bundled into `target/apigee-map.jar`
(maven-shade-plugin): the jar always runs on its own with `java -jar`.

## Usage

```bash
./apigee-map path/to/my-proxy                                      # text report
./apigee-map path/to/my-proxy -s path/to/sharedflows               # + recursive resolution of shared flows
./apigee-map path/to/my-proxy -s path/to/sharedflows -o map.html   # HTML report with a graph
./apigee-map path/to/my-proxy -f json                              # JSON (tooling, CI)
./apigee-map path/to/my-proxy -f mermaid > map.mmd                 # Mermaid graph only
./apigee-map path/to/my-proxy --strict                             # exit code 3 on errors (CI)
```

`-s` is repeatable; each folder is searched for `sharedflowbundle/` folders, indexed by the `name` of their
descriptor and by the name of their parent folder.

Bundled example: `./apigee-map examples/orders-api -s examples/sharedflows`.

## What is detected

| Dependency | Source |
|---|---|
| Virtual hosts | `ProxyEndpoint/HTTPProxyConnection/VirtualHost` (none = every vhost of the environment) |
| Shared flows | `FlowCallout/SharedFlowBundle`, followed recursively (cycle detection) |
| Target servers | `LoadBalancer/Server` (TargetEndpoint and ServiceCallout), algorithm, fallback |
| URLs | `HTTPTargetConnection/URL`, `RouteRule/URL` (hardcoded or dynamic), `httpClient` / `new Request(...)` calls in JavaScript |
| Proxy chaining | `LocalTargetConnection` (`APIProxy`/`ProxyEndpoint` or `Path`) |
| KVMs | `KeyValueMapOperations`: map, scope (`environment` by default), operations, keys, encrypted (`private.`) |
| Caches | `LookupCache`, `PopulateCache`, `InvalidateCache`, `ResponseCache`: resource (or the default shared cache), scope, key, TTL |
| Keystores / truststores | `SSLInfo` (`ref://` → reference), key alias, client auth |
| Resources | `jsc://`, `java://`, `xsl://`, `py://`: in the bundle, or expected at environment/organization level |
| Syslog | `MessageLogging/Syslog` |

Each dependency tells **who** uses it (policy, endpoint) and **where** (endpoint › flow › phase, with the effective
condition). A disabled policy (`enabled="false"`) or a policy attached to no flow makes its dependencies
**inactive** (dashed in the graph).

Issues reported by the analysis:

| Severity | Issue |
|---|---|
| ERROR | Step referencing a policy missing from `policies/` |
| ERROR | RouteRule pointing to an unknown TargetEndpoint |
| ERROR | FlowCallout that declares no `SharedFlowBundle` |
| ERROR | Shared flow that cannot be analyzed |
| WARN | Shared flow not found in the `--sharedflows` folders |
| WARN | Circular shared flow call |
| WARN | Resource not in the bundle |
| WARN | Hardcoded URL |
| WARN | ServiceCallout that declares no target connection |
| WARN | JavaScript that cannot be parsed, or scripts that cannot be read |
| INFO | Dependency resolved at runtime from a variable (`{variable}`) |
| INFO | `target.url` overridden at runtime |
| INFO | Disabled policy, or policy attached to no flow (its dependencies are inactive) |
| INFO | ProxyEndpoint that declares no VirtualHost |
| INFO | TargetEndpoint referenced by no RouteRule |
| INFO | Shared flows not resolved (no `--sharedflows`) |

## Web UI

```bash
java -jar target/apigee-map.jar ui                    # opens http://127.0.0.1:8765 in the browser
java -jar target/apigee-map.jar ui --port 9000 --no-browser --settings ./settings.json
```

The server is part of the jar (JDK only) and listens on `127.0.0.1` only: the UI cannot be reached from the
network (Mermaid is loaded from a CDN to draw the dependency graph).

- **Proxies**: every `apiproxy/` found under the proxies folder, with errors, warnings, automatic fixes and
  migration status; search and filters.
- **Proxy detail**: filterable findings, **file-by-file preview of the changes (diff)**, resources to create on the
  hybrid side, dependency map, flow variables, history; *Apply migration* button (writes to
  `<output folder>/<proxy>/`, asks before replacing an existing migration) and HTML report export. A finding can
  be marked as a **false positive**, with a reason: it is no longer reported nor counted, its automatic fix is not
  applied, and it stays listed under *Marked as false positives*, where it can be reported again.
- **Overview**: every proxy at once, most frequent rules and consolidated inventory of the hybrid resources.
- **Settings**: proxies folder, shared flows folders, output folder, enabled rules, severity per rule, naming
  prefixes accepted per policy type, false positives. Saved to `~/.apigee-map/settings.json`.

## Migration to Apigee hybrid

```bash
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows                      # diagnosis only (nothing is written)
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows -o migration.html    # filterable HTML report
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows --out migrated/      # + rewritten bundles
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows --in-place           # fixes the bundles themselves, with history
./apigee-map migrate path/to/my-proxy --strict                                    # exit code 3 if a manual error remains (CI)
```

The proxy **and the shared flows it calls** (recursively) are migrated together. With `--out` (an empty folder),
you get `<proxy>/apiproxy/`, `sharedflows/<name>/sharedflowbundle/` and, when needed, `targetservers.json` in the
management API format. The source bundles are not changed; untouched files are copied as is. With `--in-place`,
the automatic fixes are written to the bundles themselves, one history step per rule (see
[Bundle history](#bundle-history)).

Examples: `./apigee-map migrate examples/orders-api -s examples/sharedflows` and
`./apigee-map migrate examples/legacy-edge-api` (a proxy that gathers the constructs specific to Edge OPDK).

| Rule | Check | Fix |
|---|---|---|
| HYB-01 | `StatisticsCollector` not supported | **auto**: rewritten as `DataCapture` (+ data collectors to create) |
| HYB-02 | `VirtualHost` ignored by hybrid | **auto**: removed (hostnames go to the environment group) |
| HYB-03 | `ConcurrentRatelimit`, `Ldap`, `OAuthV1`, `GetOAuthV1Info`, `DeleteOAuthV1Info`, `ConnectorCallout` not supported | manual |
| HYB-04 | Node.js (`ScriptTarget`) or `HostedTarget` target, orphan `node`/`hosted` resources | manual |
| HYB-05 | `MessageLogging` to a local file | manual (Syslog / CloudLogging) |
| HYB-06 | `jsc://`… resource outside the bundle (no organization resources in hybrid) | manual |
| HYB-07 | Keystore / truststore named directly rather than through a reference | manual |
| HYB-08 | Backend, ServiceCallout or `httpClient` call on `localhost` / `127.0.0.1` | manual |
| HYB-09 | ExtractVariables JSONPath to retest (newer JSONPath engine in hybrid) | manual |
| HYB-10 | Several ProxyEndpoints (error above 10) | manual |
| HYB-11 | `virtualhost.*` variables (conditions, templates, JavaScript): no virtual hosts in hybrid | manual |
| HYB-12 | JavaScript that Rhino cannot parse | manual |
| HYB-13 | Calls to the Edge management API (`/v1/o/…`, `/v1/organizations/…`, `api.enterprise.apigee.com`, port 8080) from a TargetEndpoint, a ServiceCallout (URL, or `Path` behind a target server), a `target.url` or a JavaScript | manual |
| HYB-14 | URLs whose host is only known at runtime (TargetEndpoint, ServiceCallout, `target.url` of an AssignMessage, calls and `target.url` in JavaScript): HYB-08, HYB-13 and SEC-05 cannot check them | manual |
| SEC-01 | No authentication in the proxy nor its shared flows | manual |
| SEC-02 | No protection against malicious payloads | manual |
| SEC-03 | Credentials in clear text (AssignMessage, JS, KVM InitialEntries, URL); URLs, paths and names like `*Url`, `*Endpoint`… do not count | manual |
| SEC-04 | Secret read from a KVM into a variable that is not `private.` (visible in Debug) | manual |
| SEC-05 | Backend TLS without truststore, obsolete protocols, plain HTTP | manual |
| SEC-06 | CORS `Access-Control-Allow-Origin: *` | manual |
| PERF-01 | `MessageLogging` outside the PostClientFlow, including through nested shared flows | manual |
| PERF-02 | JavaScript blocking on `httpClient` + `waitForComplete()` | manual |
| PERF-03 | JavaScript that only assigns constants (→ AssignMessage) | manual |
| PERF-04 | Python (Jython) policy | manual |
| PERF-05 | Quota not distributed or synchronous | manual |
| PERF-06 | `PopulateCache` / `ResponseCache` without `ExpirySettings` | manual |
| DES-01 | Hardcoded URL in a TargetEndpoint | **auto**: `LoadBalancer` + TargetServer + `Path` |
| DES-02 | Disabled policy still attached | manual |
| DES-03 | Same condition repeated on ≥ 3 steps | manual (conditional flow) |
| DES-04 | No `DefaultFaultRule` | manual |
| DES-05 | Identical policies between the proxy and its shared flows (name and DisplayName ignored) | manual |
| DES-06 | Policy name without a type prefix (`AM-`, `KVM-`…) | manual |
| DES-07 | Policy attached to no flow | **auto**: removed (and removed from the descriptor) |
| DES-08 | Policies of the same type that differ by only 1 or 2 values (proxy + shared flows) | manual (one parameterized policy) |
| DES-09 | Same step sequence repeated in several flows | manual (shared flow or PreFlow) |
| DES-10 | Identical (comments aside) or 80 % similar JS/Python scripts | manual |
| DES-11 | Step sequence that redoes an available shared flow (`-s` folders) | manual (FlowCallout) |
| DES-12 | Variable read by a script but set by no policy of the proxy nor its shared flows | manual |
| DES-13 | Variable read by a step before the step that sets it, in execution order | manual |

The report also lists **what to create on the hybrid side**: KVMs (with keys and scope), target servers, caches,
keystores / references, data collectors, environment resources, shared flows to deploy, environment group
hostnames, outbound network flows (syslog).

Rules live in `migration/` (`HybridRules`, `SecurityRules`, `PerformanceRules`, `DesignRules`): a rule is a function
that reads the analysis report and the bundle DOM, reports findings and can rewrite the bundle through
`BundleWorkspace`. Each finding declares the files it targets (`ctx.on(policy)`, `ctx.on(script)`,
`ctx.onFile(...)`, or `MigrationContext.wholeBundle()`).

## Variable flow

`apigee-map variables` follows the flow variables of a bundle in the order Apigee runs its steps: what each step
reads and writes and, for each read, the steps that set the variable before it.

```bash
./apigee-map variables examples/orders-api -s examples/sharedflows             # whole bundle
./apigee-map variables examples/orders-api --policy KVM-Get-Config            # one policy, and who reads what it sets
./apigee-map variables examples/orders-api -f json                            # JSON
```

- **Order.** For each ProxyEndpoint and each TargetEndpoint its RouteRules reach: proxy request (PreFlow,
  conditional Flows, PostFlow), RouteRules, target request, target response, proxy response, PostClientFlow.
  Conditional flows and steps count as possibly running. FaultRules can follow any step: they see every variable
  set elsewhere. Two targets are two separate paths.
- **Reads and writes per policy** (`analysis/PolicyVariables`): `ref`, `*Ref` and `assignTo` attributes, `Source`,
  `AssignTo`, `OutputVariable`, `{variable}` templates (AssignMessage, RaiseFault, ServiceCallout, MessageLogging),
  message parts changed by AssignMessage (`request.header.X`…), variables extracted by ExtractVariables, conditions
  of steps, flows and RouteRules, JavaScript scripts (Rhino syntax tree) and Python. A FlowCallout brings what its
  shared flow reads and writes, when it is resolved (`-s`).
- **Status of each read**: set before (with the steps), built-in (set by Apigee), set later (DES-13), set nowhere, or
  unknown when an earlier step may set variables that cannot be named (Java callout, name computed in a script,
  unresolved shared flow).
- **Built-in, checked.** For `request`, `response`, `message`, `proxy`, `client`, `target`, `system`,
  `environment`, `organization`, `apiproxy`, `virtualhost` and `current`, the second segment must be a field Apigee
  sets: `request.heder.x` is "set nowhere", with the suggestion `request.header?`. Variables a policy sets under its
  name (`verifyapikey.VA-x.*`, `lookupcache.LC-x.*`, `ratelimit.Q-x.*`, `jwt.*`, `responsecache.*`,
  `servicecallout.SC-x.*`…) are not built-in: they are set by that policy's step, so set later if it runs after, or
  set nowhere if no policy of that name runs.

In the UI, the **Variables** tab of a proxy shows the same (`GET /api/variables?id=`): by default the reads to check
(set later, nowhere or maybe); clicking a variable follows it from the step that sets it to the steps that read it.

## Finding context

`apigee-map context` gathers what it takes to fix a `migrate` finding by hand.

```bash
./apigee-map context examples/factorization-api --rule HYB-11                # lists the 3 HYB-11 findings
./apigee-map context examples/factorization-api --rule HYB-11 --at JS-Audit  # Markdown
./apigee-map context examples/orders-api -s examples/sharedflows --rule PERF-01 -f json
```

- **Picking the finding.** `--rule` and, when the rule has several, `--at`: a text of the location. A location equal
  to the text wins (`--at JS-Audit` does not pick `JS-Audit-Copy`).
- **What the finding targets.** Each rule declares, when it creates the finding, the files it concerns
  (`Finding.subjects`: bundle + path): policies, scripts with the policy that runs them, endpoints, including in
  shared flows (PERF-01 points to the FlowCallout and to the MessageLogging of the shared flow). A finding on the
  whole bundle (SEC-01, SEC-02) declares none.
- **Policies.** For each one: where it runs (endpoint, flow, phase, condition), what it reads with the steps that set
  it, and the steps that read what it sets.
- **Files.** The XML of these policies, their scripts, the endpoints they are attached to, the XML of the policies
  that set or read their variables, and the other declared files. A finding on the whole bundle gets the descriptor
  and the endpoints.
- **Formats.** Markdown, to read, or JSON (`FixContextRenderer.model`) for tooling.

## Bundle history

To work directly on working copies of the bundles, step by step as in a git project: each change is a step that can
be shown as a diff or reverted.

```bash
./apigee-map migrate my-proxy -s sharedflows --in-place    # one step per rule that fixes the bundle
./apigee-map history my-proxy                              # steps, and changed files not recorded yet
./apigee-map history my-proxy --record "Base path v2"      # records changes made by hand
./apigee-map history my-proxy --diff 9729f64               # what a step changed
./apigee-map history my-proxy --diff original              # everything changed since the original state
./apigee-map history my-proxy --revert 9729f64             # reverts a step with a new step
```

- **One git repository per bundle** (JGit, nothing to install), created on first use with a first `Original` step:
  the bundle as it is. The repository lives outside the bundle, in
  `~/.apigee-map/history/<name>-<path hash>.git` (`--history <dir>` for another folder): it does not end up in the
  migrated bundles and does not get in the way of a git repository the bundle already belongs to. It is tied to the
  bundle path: a moved bundle starts a new history.
- **`migrate --in-place`** fixes the proxy and the shared flows it calls (each with its own history). Changes made by
  hand since the last step are recorded first (`Manual changes`), then each rule that changes a bundle writes its
  changes and becomes a step (`HYB-02 VirtualHost is ignored by hybrid`, with the details of the changes). Run again,
  it finds nothing left to fix and adds no step.
- **Reverting** a step creates a `Revert "…"` step; later steps are kept. If one of them changes the same lines,
  nothing is changed and the command lists the conflicting files. Pending changes must be recorded first. Reverting
  an automatic fix is not enough to discard it: the next `migrate --in-place` applies it again, unless the rule is
  disabled.
- **In the UI**, the **History** tab of a proxy lists the steps with their diff and can revert one.

## Limits

- Static analysis: names computed at runtime (`{variable}`) are reported, not resolved.
- Flow hooks and environment resources (actual existence of KVMs, caches, target servers…) are not visible from the
  bundle alone.
- The link to API products / developer apps is not covered (it lives in the organization).
- Migration: manual fixes (rewriting JavaScript, replacing an unsupported policy…) are not automated, and nothing is
  deployed. In rewritten XML files, the attributes of each element are reordered alphabetically (the content does
  not change).

## Structure

- `analysis/`: bundle location, XML parsing, extraction per policy type, shared flow resolution, variable flow
  (`PolicyVariables`, `VariableFlow`)
- `model/`: report records
- `render/`: text, JSON, Mermaid and HTML outputs (dependency map, migration report, variable flow, finding context)
- `migration/`: hybrid migration rules, bundle rewriting, inventory of the resources to create, finding context
  (`FixContext`)
- `ui/`: local HTTP server, JSON API, settings; pages in `src/main/resources/ui/` (HTML/CSS/JS, no build)
- `history/`: history of bundles changed in place (`SourceHistory`, one git repository per bundle through JGit),
  text diffs (`Diffs`)
