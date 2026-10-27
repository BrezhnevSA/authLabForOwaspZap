package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.MONGO_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sleepSecondsOrMillisWithMargin;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import io.swagger.v3.oas.annotations.Parameter;
import java.util.Map;
import java.util.regex.Matcher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** LDAP and document-database reproductions. */
@RestController
public class DirectoryAndNoSqlAlertsController {

    @RequestMapping(value = "/vulnApp/ldapInjection", method = RequestMethod.GET)
    public ResponseEntity<String> ldapInjection(@RequestParam("user") String user) {
        String lower = safeLower(user);
        if (lower.contains("*") || lower.contains(")(") || lower.contains("|") || lower.contains("&")) {
            return text("LDAP result: uid=admin,ou=people,dc=example,dc=org\nuid=guest,ou=people,dc=example,dc=org");
        }
        if (user.contains("(") || user.contains(")")) {
            return text("javax.naming.InvalidSearchFilterException: Unbalanced parenthesis");
        }
        return text("LDAP result: uid=" + user);
    }

    @RequestMapping(value = "/vulnApp/noSqlInjectionMongo", method = RequestMethod.GET)
    public ResponseEntity<String> noSqlInjectionMongo(
        @RequestParam(value = "filter", required = false, defaultValue = "baseline") String filter,
        @Parameter(hidden = true) @RequestParam Map<String, String> params
    ) {
        String original = filter;

        // ZAP 40033 boolean/all-data probes add parameter names such as filter[$ne],
        // filter[$regex], filter[$gt]. Counter-proof filter[$eq] should look like the baseline.
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue() == null ? "" : entry.getValue();
            String lowerKey = safeLower(key);
            String lowerValue = safeLower(value);

            if (lowerKey.contains("[$eq]")) {
                return baselineMongoResponse(original);
            }
            if (lowerKey.contains("[$ne]") || lowerKey.contains("[$regex]") || lowerKey.contains("[$gt]")) {
                return allDataMongoResponse();
            }
            if (lowerValue.contains("$ne") || lowerValue.contains("$regex") || lowerValue.contains("$gt") || lowerValue.contains("true")) {
                return allDataMongoResponse();
            }

            Matcher timing = MONGO_SLEEP_PATTERN.matcher(value);
            if (timing.find()) {
                sleepSecondsOrMillisWithMargin(Double.parseDouble(timing.group(1)));
                return json("{\"users\":[\"admin\",\"guest\",\"zap\"],\"timing\":true}");
            }

            if (lowerValue.contains("runtimeexception") || lowerValue.contains("mongoresultexception") || lowerValue.contains("});") || lowerValue.contains("//")) {
                return text("MongoResultException: RuntimeException: SyntaxError: unterminated string literal");
            }
        }
        return baselineMongoResponse(original);
    }

    private ResponseEntity<String> baselineMongoResponse(String filter) {
        return json("{\"users\":[\"" + filter.replace("\"", "'") + "\"]}");
    }

    private ResponseEntity<String> allDataMongoResponse() {
        return json("{\"users\":[\"admin\",\"guest\",\"zap\"]}");
    }
}
