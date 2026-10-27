# Additional ZAP alert reproduction notes

This package adds optional endpoints for alerts that were previously considered non-stable or environment-dependent.

## Passive/header alerts

Endpoints:

- `/vulnApp/passive/missingSecurityHeaders`
- `/vulnApp/passive/cookieWithoutSameSite`
- `/vulnApp/passive/cookieSameSiteNone`
- `/vulnApp/passive/cookieInvalidSameSite`
- `/vulnApp/passive/serverHeaderLeak`
- `/vulnApp/passive/timestampDisclosure`
- `/vulnApp/passive/hstsOnHttp`
- `/vulnApp/passive/errorWithoutNosniff`

Expected alerts:

- `10020-1` Missing Anti-clickjacking Header
- `10021` X-Content-Type-Options Header Missing
- `10038-1` Content Security Policy Header Not Set
- `10054-1` Cookie without SameSite Attribute
- `10054-2` Cookie with SameSite Attribute None
- `10054-3` Cookie with Invalid SameSite Attribute
- `10036-1` / `10036-2` HTTP Server Response Header, environment-dependent
- `10096` Timestamp Disclosure - Unix
- `10035-4` HSTS header on plain HTTP

`10035-1` Strict-Transport-Security Header Not Set needs HTTPS traffic without HSTS. A plain HTTP-only scan will not reliably produce that exact variant.

## DOM XSS

Endpoint:

- `/vulnApp/domXss?name=ZAP`

Expected alert:

- `40026` Cross Site Scripting (DOM Based)

Requirements:

- DOM XSS add-on installed.
- Selenium/browser support installed and working.
- Rule `40026` enabled.

## Spring4Shell

Endpoint:

- `/vulnApp/spring4shell`

Expected alert:

- `40045` Spring4Shell

This is a safe behavioral emulation for ZAP: it returns HTTP 400 for `class.module.classLoader.DefaultAssertionStatus=nonsense` and 200 for the safe payload. It does not add a real vulnerable Spring4Shell dependency.

## React2Shell

Endpoint:

- `/vulnApp/react2shell`

Expected alert:

- `40048` Remote Code Execution (React2Shell)

Requirements:

- Technologies include React or Next.js, or context technologies are unrestricted/all-enabled.
- Rule `40048` enabled.

This is a safe behavioral emulation for ZAP: it returns HTTP 500 with `E{\"digest\"` evidence for ZAP's malformed React Server Components multipart request. It does not add a real vulnerable Next.js/React server.

## SOAP

Endpoints:

- `/vulnApp/soap?wsdl`
- `/vulnApp/soap`

Expected alerts:

- `90026` SOAP Action Spoofing
- `90029` SOAP XML Injection

Requirements:

- SOAP add-on installed.
- Import the WSDL with the SOAP add-on, not just the normal OpenAPI importer.
- Rules `90026` and `90029` enabled.

## Log4Shell and script scan rules

Not implemented as a fake Spring endpoint.

- `40043` Log4Shell requires OAST interaction and a target that performs vulnerable Log4j JNDI lookup. Adding a real vulnerable Log4j runtime is dangerous and should be isolated in a separate container/profile if needed.
- `50000` Script Active Scan Rules is not an application vulnerability by itself. It appears only when you load custom active scan scripts into ZAP.

## 2026-08-19: fixes for missed active/passive alerts

This package includes additional matcher fixes for rules that were missed in the previous scan:

- 40020 Hypersonic SQL timing now matches ZAP's quoted `"java.lang.Thread.sleep"(milliseconds)` payload.
- 90021 XPath Injection now returns a literal `XPathException` evidence for ZAP's `"'`, `<!--`, and `]]>` probes.
- 90023 XXE returns passwd-like evidence for `zapxxe`/DOCTYPE payloads so local-file reflection works even without an OAST callback.
- 90019 Server Side Code Injection now handles PHP `chr(...)` payloads and ASP `response.write(a*b)` payloads.
- 90035/90036 SSTI now evaluates delimiter-wrapped arithmetic such as `zj{{123*456}}zj` and template-wrapped `sleep N` probes.
- 90025 Expression Language Injection now evaluates `${n+n}`.
- 40033 and 90039 MongoDB NoSQL now handle query parameter pollution (`filter[$ne]`, `filter[$eq]`) and Mongo-style `sleep(N)` JavaScript payloads.
- 90034 Cloud Metadata now exposes AWS/GCP-style metadata roots at `/latest/meta-data/` and `/computeMetadata/v1/`.
- 40008 Parameter Tampering now returns Java servlet-style error evidence for ZAP's tamper values.
- 30001 Buffer Overflow now returns HTTP 500 with `Connection: close` for 2100+ char payloads.
- 90024 Padding Oracle has a discoverable valid hex token: `ffffffffffffffffffffffffffffff10`.
- 40034 .env now returns `application/octet-stream` plus comment/key-value content.
- 40028 ELMAH body now contains case-sensitive `Error Log for` evidence.
- 40042 Spring Actuator now includes `/actuator/health`.

Rules that still need environment/tooling, not just endpoints:

- 90023 XXE: OAST helps for remote/OOB detection, local reflection is simulated here.
- 40033/90039: install `ascanrulesBeta` and include MongoDB technology.
- 40045 Spring4Shell: include Spring technology.
- 40048 React2Shell: include React/Next.js technology.
- 90026/90029 SOAP: import `/vulnApp/soap?wsdl` through the SOAP add-on, not only OpenAPI.

## 2026-10-06: required vulnerability coverage additions

The following fixtures were added after comparing the required test matrix with an actual ZAP scan:

- `90002` Java Serialized Object (coverage for Insecure Serialization / CWE-502):
  `/vulnApp/passive/javaSerializedObject` returns a response beginning with Java serialization magic `AC ED 00 05`.
- `10023` Information Disclosure - Debug Error Messages:
  `/vulnApp/passive/debugErrorMessage` returns a deterministic SQL Server debug error fragment.
- `10024` Information Disclosure - Sensitive Information in URL:
  `/vulnApp/passive/sensitiveUrl?email=qa.user@example.com` gives deterministic e-mail evidence.
- `10027` Information Disclosure - Suspicious Comments:
  `/vulnApp/passive/suspiciousComments` contains TODO/FIXME comments.
- `40012` Cross Site Scripting (Reflected):
  `/vulnApp/cssw/html?name=baseline` now explicitly returns `text/html` and reflects the input unescaped.
- `40012` Cross Site Scripting Weakness (Reflected in JSON Response):
  `/vulnApp/reflectedXssJson?name=baseline` reflects the input in an `application/json` response.
  **ZAP only raises this JSON variant at LOW threshold for rule 40012.**
- `90023` XML External Entity Attack:
  the OpenAPI definition for `/vulnApp/xxe` now includes a valid XML baseline body (`<foo>baseline</foo>`), which lets the rule's reflected local-file test mutate a real XML element at MEDIUM attack strength.
- `40035` Hidden File Finder:
  additional canonical paths are available: `/CVS/Root`, `/.git/HEAD`, `/.svn/entries`, plus the existing `/.git/config` and `/WEB-INF/web.xml`.
- Vulnerable standard client component / delivery chain coverage:
  the root page references `/jquery-1.8.3.min.js`, deliberately advertising jQuery 1.8.3 for the Retire.js add-on.
- JS Prototype Pollution:
  `/vulnApp/prototypePollution` contains a deliberately unsafe query-string-to-property-path write. Detection requires the OWASP PTK beta integration / Client Spider and should produce the `210008` family (for example `210008-2`). This is not a classic server-side active-scan rule.

The root page links to all passive/browser fixtures so the spiders can discover them without relying only on OpenAPI.
