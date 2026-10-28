# apigee-map

Cartographie des dépendances d'un **API proxy** ou d'un **shared flow** Apigee **OPDK**, à partir du bundle local
(dossier `apiproxy/` / `sharedflowbundle/` ou zip exporté). Aucun appel à la Management API.

## Build

```bash
JAVA_HOME=~/Library/Java/JavaVirtualMachines/openjdk-21.0.2/Contents/Home mvn package
```

Hors VPN, passer un `settings.xml` vide (`-s empty-settings.xml`) pour résoudre depuis Maven Central.

## Utilisation

```bash
./apigee-map path/to/my-proxy                                  # rapport texte
./apigee-map path/to/my-proxy -s path/to/sharedflows           # + résolution récursive des shared flows
./apigee-map path/to/my-proxy -s path/to/sharedflows -o map.html   # rapport HTML avec graphe
./apigee-map path/to/my-proxy -f json                          # JSON (outillage, CI)
./apigee-map path/to/my-proxy -f mermaid > map.mmd             # graphe Mermaid seul
./apigee-map path/to/my-proxy --strict                         # code retour 3 si erreurs (CI)
```

`-s` est répétable ; chaque dossier est parcouru à la recherche de `sharedflowbundle/`, indexés par le `name`
du descripteur et par le nom du dossier parent.

Exemple fourni : `./apigee-map examples/orders-api -s examples/sharedflows`.

## Ce qui est détecté

| Dépendance | Source |
|---|---|
| Virtual hosts | `ProxyEndpoint/HTTPProxyConnection/VirtualHost` (absence = tous les vhosts de l'env) |
| Shared flows | `FlowCallout/SharedFlowBundle`, suivis récursivement (détection de cycles) |
| Target servers | `LoadBalancer/Server` (TargetEndpoint et ServiceCallout), algorithme, fallback |
| URLs | `HTTPTargetConnection/URL`, `RouteRule/URL` (en dur ou dynamiques) |
| Proxy chaining | `LocalTargetConnection` (`APIProxy`/`ProxyEndpoint` ou `Path`) |
| KVM | `KeyValueMapOperations` : map, scope (défaut `environment`), opérations, clés, chiffré (`private.`) |
| Caches | `LookupCache`, `PopulateCache`, `InvalidateCache`, `ResponseCache` : ressource (ou cache partagé par défaut), scope, clé, TTL |
| Keystores / truststores | `SSLInfo` (`ref://` → référence), key alias, client auth |
| Ressources | `jsc://`, `java://`, `xsl://`, `py://` : présentes dans le bundle ou attendues au niveau env/org |
| Syslog | `MessageLogging/Syslog` |

Chaque dépendance indique **qui** l'utilise (policy, endpoint) et **où** (endpoint › flow › phase, avec condition
effective). Une policy désactivée (`enabled="false"`) ou attachée à aucun flow rend ses dépendances **inactives**
(pointillés dans le graphe).

Contrôles remontés : step vers une policy absente, RouteRule vers un TargetEndpoint inconnu, shared flow
introuvable, appel circulaire, ressource absente du bundle, URL en dur, référence dynamique, policy orpheline ou
désactivée, surcharge de `target.url`.

## Interface web

```bash
java -jar target/apigee-map.jar ui                    # ouvre http://127.0.0.1:8765 dans le navigateur
java -jar target/apigee-map.jar ui --port 9000 --no-browser --settings ./settings.json
```

Le serveur est inclus dans le jar (aucune dépendance) et n'écoute que sur `127.0.0.1` : l'interface n'est pas
joignable depuis le réseau et rien ne sort du poste (sauf Mermaid, chargé depuis un CDN pour dessiner le graphe de
dépendances).

- **Proxies** : tous les `apiproxy/` trouvés sous le dossier des proxies, avec erreurs, avertissements, corrections
  automatiques et statut de migration ; recherche et filtres.
- **Détail d'un proxy** : findings filtrables, **aperçu des changements fichier par fichier (diff)**, ressources à
  créer côté hybrid, cartographie des dépendances ; bouton *Apply migration* (écrit dans
  `<dossier de sortie>/<proxy>/`, confirmation avant de remplacer une migration existante) et export du rapport HTML.
- **Overview** : tous les proxies d'un coup, règles les plus fréquentes et inventaire consolidé des ressources hybrid.
- **Settings** : dossier des proxies, dossiers des shared flows, dossier de sortie, règles actives, gravité par
  règle, préfixes de nommage acceptés par type de policy. Enregistré dans `~/.apigee-map/settings.json`.

## Migration vers Apigee hybrid

```bash
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows                      # diagnostic seul (rien n'est écrit)
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows -o migration.html    # rapport HTML filtrable
./apigee-map migrate path/to/my-proxy -s path/to/sharedflows --out migrated/      # + bundles réécrits
./apigee-map migrate path/to/my-proxy --strict                                    # code retour 3 s'il reste une erreur manuelle (CI)
```

Le proxy **et les shared flows qu'il appelle** (récursivement) sont migrés ensemble. Avec `--out` (dossier vide),
on obtient `<proxy>/apiproxy/`, `sharedflows/<nom>/sharedflowbundle/` et, si besoin, `targetservers.json` au format
de l'API de management. Les bundles sources ne sont jamais modifiés ; les fichiers non concernés sont copiés tels
quels.

Exemples : `./apigee-map migrate examples/orders-api -s examples/sharedflows` et
`./apigee-map migrate examples/legacy-edge-api` (proxy qui cumule les constructions propres à Edge OPDK).

| Règle | Contrôle | Correction |
|---|---|---|
| HYB-01 | `StatisticsCollector` non supporté | **auto** : réécrit en `DataCapture` (+ data collectors à créer) |
| HYB-02 | `VirtualHost` ignoré par hybrid | **auto** : supprimé (hostnames à porter dans l'environment group) |
| HYB-03 | `ConcurrentRatelimit`, `Ldap`, `OAuthV1`, `GetOAuthV1Info`, `DeleteOAuthV1Info`, `ConnectorCallout` non supportés | manuelle |
| HYB-04 | Cible Node.js (`ScriptTarget`) ou `HostedTarget`, ressources `node`/`hosted` orphelines | manuelle |
| HYB-05 | `MessageLogging` vers fichier local | manuelle (Syslog / CloudLogging) |
| HYB-06 | Ressource `jsc://`… hors du bundle (pas de ressources d'organisation dans hybrid) | manuelle |
| HYB-07 | Keystore / truststore nommé directement plutôt que via une référence | manuelle |
| HYB-08 | Backend ou ServiceCallout sur `localhost` / `127.0.0.1` | manuelle |
| HYB-09 | JSONPath d'ExtractVariables à retester (moteur JSONPath plus récent dans hybrid) | manuelle |
| HYB-10 | Plusieurs ProxyEndpoints (erreur au-delà de 10) | manuelle |
| SEC-01 | Aucune authentification dans le proxy ni ses shared flows | manuelle |
| SEC-02 | Aucune protection contre les payloads malveillants | manuelle |
| SEC-03 | Secrets en clair (AssignMessage, JS, InitialEntries de KVM, URL) | manuelle |
| SEC-04 | Secret lu depuis une KVM dans une variable non `private.` (visible en Debug) | manuelle |
| SEC-05 | TLS backend sans truststore, protocoles obsolètes, HTTP en clair | manuelle |
| SEC-06 | CORS `Access-Control-Allow-Origin: *` | manuelle |
| PERF-01 | `MessageLogging` hors PostClientFlow, y compris via shared flows imbriqués | manuelle |
| PERF-02 | JavaScript bloquant sur `httpClient` + `waitForComplete()` | manuelle |
| PERF-03 | JavaScript qui ne fait qu'assigner des constantes (→ AssignMessage) | manuelle |
| PERF-04 | Policy Python (Jython) | manuelle |
| PERF-05 | Quota non distribué ou synchrone | manuelle |
| PERF-06 | `PopulateCache` / `ResponseCache` sans `ExpirySettings` | manuelle |
| DES-01 | URL en dur dans un TargetEndpoint | **auto** : `LoadBalancer` + TargetServer + `Path` |
| DES-02 | Policy désactivée mais toujours attachée | manuelle |
| DES-03 | Même condition répétée sur ≥ 3 steps | manuelle (flow conditionnel) |
| DES-04 | Pas de `DefaultFaultRule` | manuelle |
| DES-05 | Policies identiques entre le proxy et ses shared flows | manuelle |
| DES-06 | Nom de policy sans préfixe de type (`AM-`, `KVM-`…) | manuelle |
| DES-07 | Policy attachée à aucun flow | **auto** : supprimée (et retirée du descripteur) |

Le rapport liste aussi **ce qu'il faut créer côté hybrid** : KVM (avec clés et scope), target servers, caches,
keystores / références, data collectors, ressources d'environnement, shared flows à déployer, hostnames
d'environment group, flux réseau sortants (syslog).

Les règles sont dans `migration/` (`HybridRules`, `SecurityRules`, `PerformanceRules`, `DesignRules`) : une règle
est une fonction qui lit le rapport d'analyse et le DOM du bundle, signale des findings et peut réécrire le bundle
via `BundleWorkspace`.

## Limites

- Analyse statique : les noms calculés à l'exécution (`{variable}`) sont signalés, pas résolus.
- Les flow hooks et les ressources d'environnement (existence réelle des KVM, caches, target servers…) ne sont
  pas visibles depuis le bundle seul.
- L'association aux API products / developer apps n'est pas couverte (elle vit dans l'organisation).
- Migration : les corrections manuelles (réécriture de JavaScript, remplacement d'une policy non supportée…) ne sont
  pas automatisées, et rien n'est déployé. Dans les fichiers XML réécrits, les attributs de chaque élément sont
  réordonnés alphabétiquement (le contenu ne change pas).

## Structure

- `analysis/` : localisation du bundle, parsing XML, extraction par type de policy, résolution des shared flows
- `model/` : records du rapport
- `render/` : sorties texte, JSON, Mermaid, HTML (cartographie et rapport de migration)
- `migration/` : règles de migration vers hybrid, réécriture des bundles, inventaire des ressources à créer
- `ui/` : serveur HTTP local, API JSON, réglages ; pages dans `src/main/resources/ui/` (HTML/CSS/JS sans build)
