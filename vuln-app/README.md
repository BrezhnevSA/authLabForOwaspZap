# Vulnerable app for owasp/zap testing

This app mocks some of the alerts from the owasp\zap tool. Use it to test your owasp\zap instance.

Mocked alerts (!!! - temporary not found by scan, in dev):

### SQL

| ID / AlertRef | Alert name                                  | Where catch                                                                                                   |
|---------------|---------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| 40018         | SQL Injection                               | /app/vulnApp/xpathInjection /app/vulnApp/soap /app/vulnApp/externalRedirect /app/comment/                     |
| 40019         | SQL Injection - MySQL (Time Based)          | /app/vulnApp/sqlInjectionMySqlTimeBased                                                                       |
| 40020         | SQL Injection - Hypersonic SQL (Time Based) | /app/vulnApp/sqlInjectionHypersonicTimeBased                                                                  |
| 40021         | SQL Injection - Oracle (Time Based)         | /app/vulnApp/sqlInjectionOracleTimeBased                                                                      |
| 40022         | SQL Injection - PostgreSQL (Time Based)     | /app/vulnApp/sqlInjectionPostgres                                                                             |
| 40027         | SQL Injection - MsSQL (Time Based)          | /app/vulnApp/sqlInjectionMsSqlTimeBased                                                                       |
| 40024         | SQL Injection - SQLite (Time Based)         | /app/vulnApp/sqlInjectionSqLite /app/vulnApp/sqlInjectionSqLiteTimeBased /app/vulnApp/sqlInjectionSqLiteError |

### XSS

| ID / AlertRef | Alert name                                                  | Where catch            |
|---------------|-------------------------------------------------------------|------------------------|
| 40012         | Cross Site Scripting (Reflected)                            | /app/vulnApp/cssw/html |
| 40012         | Cross Site Scripting Weakness (Reflected in JSON Response)  | /app/vulnApp/cssw      |
| 40014         | Cross Site Scripting (Persistent)                           | /app/event             |
| 40014-2       | Cross Site Scripting Weakness (Persistent in JSON Response) | /app/comment           |

### XML / XPath / XSLT

| ID / AlertRef | Alert name                     | Where catch                 |
|---------------|--------------------------------|-----------------------------|
| 90017         | XSLT Injection                 | /app/vulnApp/xsltInjection  |
| 90021         | !!! XPath Injection            | /app/vulnApp/xpathInjection |
| 90023         | !!! XML External Entity Attack | /app/vulnApp/xxe            |

### Code execution / template / command injection

| ID / AlertRef | Alert name                                      | Where catch                                                                        |
|---------------|-------------------------------------------------|------------------------------------------------------------------------------------|
| 90019-1       | Server Side Code Injection - PHP Code Injection | /app/vulnApp/serverSideCodeInjection                                               |
| 90020         | Remote OS Command Injection                     | /app/vulnApp/osCommandInjection                                                    |
| 90037         | Remote OS Command Injection (Time Based)        | /app/vulnApp/osCommandInjectionTimeBased                                           |
| 90035         | Server Side Template Injection                  | /app/vulnApp/serverSideTemplateInjection                                           |
| 90036         | Server Side Template Injection (Blind)          | /app/vulnApp/serverSideTemplateInjection                                           |
| 90025         | Expression Language Injection                   | /app/vulnApp/expressionLanguageInjection /app/vulnApp/serverSideTemplateInjection  |
| 90024         | Generic Padding Oracle                          | /app/vulnApp/paddingOracle                                                         |

### LDAP / NoSQL / SSRF-cloud

| ID / AlertRef | Alert name                             | Where catch                                                              |
|---------------|----------------------------------------|--------------------------------------------------------------------------|
| 40015         | LDAP Injection                         | /app/vulnApp/ldapInjection                                               |
| 40033         | NoSQL Injection - MongoDB              | /app/vulnApp/noSqlInjectionMongo                                         |
| 90039         | NoSQL Injection - MongoDB (Time Based) | /app/vulnApp/sqlInjectionMySqlTimeBased /app/vulnApp/noSqlInjectionMongo |
| 90034         | !!! Cloud Metadata Potentially Exposed | /app/vulnApp/ssrf                                                        |

### Web misconfiguration / active checks

| ID / AlertRef     | Alert name                 | Where catch                     |
|-------------------|----------------------------|---------------------------------|
| 20019-1 / 20019-2 | External Redirect          | /app/vulnApp/externalRedirect   |
| 40040             | CORS Misconfiguration      | /app/vulnApp/cors               |
| 40008             | Parameter Tampering        | /app/vulnApp/parameterTampering |
| 30001             | Buffer Overflow            | /app/vulnApp/bufferOverflow     |
| 30002             | Format String Error        | /app/vulnApp/externalRedirect   |
| 90024             | !!! Generic Padding Oracle | /app/vulnApp/paddingOracle      |
| 90028             | !!! Insecure HTTP Method   | /app/vulnApp/insecureMethod     |

### Resource disclosure / hidden files

| ID / AlertRef   | Alert name                                                                | Where catch                                    |
|-----------------|---------------------------------------------------------------------------|------------------------------------------------|
| 40028           | !!! ELMAH Information Leak                                                | /elmah.axd or /app/vulnApp/elmah.axd           |
| 40029           | Trace.axd Information Leak                                                | /app/trace.axd or /app/vulnApp/trace.axd       |
| 40032           | .htaccess Information Leak                                                | /.htaccess or /app/vulnApp/.htaccess           |
| 40034           | !!! .env Information Leak /.env or                                        | /app/vulnApp/.env                              |
| 40035           | Hidden File Found                                                         | /.git/config, /CVS/root, mb /WEB-INF/web.xml   |
| 40042           | !!! Spring Actuator Information Leak                                      | /actuator/env, /actuator/heapdump              |
| 10045 / 10045-2 | !!! Source Code Disclosure - /WEB-INF folder / Properties File Disclosure | /WEB-INF folder                                |

### Alerts without group

| ID / AlertRef | Alert name                                                               | Where catch                                                                  |
|---------------|--------------------------------------------------------------------------|------------------------------------------------------------------------------|
| 10020         | Missing Anti-clickjacking Header                                         | different                                                                    |
| 10021         | X-Content-Type-Options Header Missing                                    | different                                                                    |
| 10035         | !!! Strict-Transport-Security Header Not Set                             |                                                                              |
| 10036         | Server Leaks Version Information via "Server" HTTP Response Header Field | /app/vulnApp/passive/serverHeaderLeak                                        |
| 10038         | Content Security Policy Header Not Set                                   |                                                                              |
| 10036         | !!! Server Leaks Information via ...                                     |                                                                              |
| 10054         | Cookie without SameSite Attribute                                        | /app/vulnApp/passive/cookieWithoutSameSite                                   |
| 10054-3       | Cookie with Invalid SameSite Attribute                                   | /app/vulnApp/passive/cookieInvalidSameSite                                   |
| 10054-2       | Cookie with SameSite Attribute None                                      | /app/vulnApp/passive/cookieSameSiteNone                                      |
| 10096         | Timestamp Disclosure - Unix                                              | /app/vulnApp/passive/timestampDisclosure                                     |
| 40026         | Cross Site Scripting (DOM Based)                                         | /app/vulnApp/sqlInjectionPostgres /app/vulnApp/domXss /app/vulnApp/cssw/html |
| 40043         | !!! Log4Shell                                                            |                                                                              |
| 40045         | Spring4Shell                                                             | /app/vulnApp/spring4shell                                                    |
| 40048         | !!! React2Shell React Server Components endpoint                         |                                                                              |
| 90026         | !!! SOAP Action Spoofing / 90029 SOAP XML Injection                      |                                                                              |
| 50000         | !!! Script Active Scan Rules                                             |                                                                              |
| 6             | Path Traversal                                                           | /app/vulnApp/osCommandInjection                                              |
| 10028         | Off-site Redirect                                                        | /app/vulnApp/externalRedirect                                                |
| 10109         | Modern Web Application                                                   | /app/vulnApp/domXss                                                          |
| 10024         | Information Disclosure - Sensitive Information in URL                    | /app/vulnApp/ldapInjection /app/vulnApp/paddingOracle                        |
| 10009         | In Page Banner Information Leak                                          | different                                                                    |
| 10098         | Cross-Domain Misconfiguration                                            | /app/vulnApp/cors                                                            |
| 10038         | Content Security Policy (CSP) Header Not Set                             | different                                                                    |
| 10038         | Application Error Disclosure                                             | /app/vulnApp/passive/errorWithoutNosniff                                     |
| 10202         | Absence of Anti-CSRF Tokens                                              | /app/ /app/vulnApp                                                           |
| 100044-3      | Suspicious Input Transformation - Expression Evaluation                  | /app/vulnApp/serverSideTemplateInjection                                     |
| 43            | Source Code Disclosure - File Inclusion                                  | different                                                                    |
| 30003         | Integer Overflow Error                                                   | /app/vulnApp/paddingOracle                                                   |
| 90027         | Cookie Slack Detector                                                    | different                                                                    |
| 90028-1       | Insecure HTTP Method - DELETE                                            | /app/vulnApp/insecureMethod                                                  |

### Required coverage added (2026-10-06)

| Required class                | ZAP alert / fixture               | Endpoint / requirement                                                                                                                   |
|-------------------------------|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Vulnerable standard component | Retire.js / Vulnerable JS Library | root page loads `/app/jquery-1.8.3.min.js`                                                                                               |
| Reflected XSS                 | 40012                             | `/app/vulnApp/cssw/html?name=baseline`                                                                                                   |
| Reflected XSS in JSON         | 40012 JSON variant                | `/app/vulnApp/reflectedXssJson?name=baseline`; rule threshold must be **LOW**                                                            |
| XXE                           | 90023                             | POST `/app/vulnApp/xxe`; OpenAPI now supplies a valid XML baseline                                                                       |
| Insecure Serialization        | 90002 Java Serialized Object      | `/app/vulnApp/passive/javaSerializedObject`                                                                                              |
| JS Prototype Pollution        | 210008 family                     | `/app/vulnApp/prototypePollution?key=__proto__&prop=headers&value=ptk-polluted`; requires OWASP PTK IAST + Client Spider/PTK Active Scan |
| Debug Error Messages          | 10023                             | `/app/vulnApp/passive/debugErrorMessage`                                                                                                 |
| Sensitive Information in URL  | 10024                             | `/app/vulnApp/passive/sensitiveUrl?email=qa.user@example.com`                                                                            |
| Suspicious Comments           | 10027                             | `/app/vulnApp/passive/suspiciousComments`                                                                                                |
| Hidden File Found             | 40035                             | host-root fixtures `/.hg`, `/.bzr`, `/._darcs`, `/BitKeeper`, `/CVS/root`, `/.git/HEAD` are created by the Docker image                  |

### **How to build and access in zap-target-lab:**

From the repository root, build this image through the shared Bake configuration:

```sh
CI_REGISTRY_IMAGE=zap-target-lab docker buildx bake --load vuln-app
```

The deployed target is `https://zap-lab-vuln-app.ast.rt-solar.ru`. The application is mounted under `/app`; use `/app/swagger-ui/index.html` for Swagger UI or the checked-in `openapi.json` for a scan. Reset the application state with `GET /app/clearData`.

### OpenAPI

https://zap-lab-vuln-app.ast.rt-solar.ru/app/v3/api-docs

https://zap-lab-vuln-app.ast.rt-solar.ru/app/swagger-ui/index.html

