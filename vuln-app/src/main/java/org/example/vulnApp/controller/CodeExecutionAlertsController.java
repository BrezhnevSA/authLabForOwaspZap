package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.OS_COMMAND_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.SSTI_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.evaluateFirstArithmeticExpression;
import static org.example.vulnApp.support.ZapAlertVulnSupport.firstMatchedNumber;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sleepSecondsOrMillisWithMargin;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** OS command, server-side code, template, and expression-language reproductions. */
@RestController
public class CodeExecutionAlertsController {
    private static final Pattern ASP_RESPONSE_WRITE_MULTIPLY = Pattern.compile(
        "response\\.write\\s*\\(\\s*(\\d{2,7})\\s*\\*\\s*(\\d{2,7})\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    @RequestMapping(value = "/vulnApp/osCommandInjection", method = RequestMethod.GET)
    public ResponseEntity<String> osCommandInjection(@RequestParam("cmd") String cmd) {
        String lower = safeLower(cmd);
        if (lower.contains("id") || lower.contains("whoami")) {
            return text("uid=0(root) gid=0(root) groups=0(root)\nroot");
        }
        if (lower.contains("cat") && lower.contains("/etc/passwd")) {
            return text("root:x:0:0:root:/root:/bin/bash");
        }
        return text("executed: " + cmd);
    }

    @RequestMapping(value = "/vulnApp/osCommandInjectionTimeBased", method = RequestMethod.GET)
    public ResponseEntity<String> osCommandInjectionTimeBased(@RequestParam("cmd") String cmd) {
        Matcher m = OS_COMMAND_SLEEP_PATTERN.matcher(cmd);
        if (m.find()) {
            sleepSecondsOrMillisWithMargin(firstMatchedNumber(m));
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/serverSideCodeInjection", method = RequestMethod.GET)
    public ResponseEntity<String> serverSideCodeInjection(@RequestParam("code") String code) {
        String lower = safeLower(code);

        // ZAP 90019-1 PHP probes print chr(122).chr(97)... and expect evidence "zap_token".
        if (lower.contains("print(") && lower.contains("chr(122)") && lower.contains("chr(95)")) {
            return text("zap_token");
        }

        // ZAP 90019-2 ASP probes response.write(<random>*<random>) and expects the product.
        Matcher asp = ASP_RESPONSE_WRITE_MULTIPLY.matcher(code);
        if (asp.find()) {
            long left = Long.parseLong(asp.group(1));
            long right = Long.parseLong(asp.group(2));
            return text(String.valueOf(left * right));
        }

        if (lower.contains("phpinfo")) {
            return text("PHP Version 8.2.0\nSystem => Linux vuln-app");
        }
        if (lower.contains("md5") || lower.contains("sha1")) {
            return text("900150983cd24fb0d6963f7d28e17f72");
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/serverSideTemplateInjection", method = RequestMethod.GET)
    public ResponseEntity<String> serverSideTemplateInjection(@RequestParam("template") String template) {
        String lower = safeLower(template);

        // ZAP 90035 wraps arithmetic payloads in delimiter "zj" and expects the rendered result
        // to remain between those delimiters, for example zj{{123*456}}zj -> zj56088zj.
        if (template.contains("zj")) {
            String result = evaluateFirstArithmeticExpression(template);
            if (result != null) {
                return text("rendered: zj" + result + "zj");
            }
        }

        String directResult = evaluateFirstArithmeticExpression(template);
        if (directResult != null && (template.contains("{{") || template.contains("${") || template.contains("#{") || template.contains("<%="))) {
            return text(directResult);
        }

        Matcher sleepMatcher = SSTI_SLEEP_PATTERN.matcher(template);
        if (sleepMatcher.find()) {
            sleepSecondsOrMillisWithMargin(Double.parseDouble(sleepMatcher.group(1)));
            return text("ok");
        }
        if (lower.contains("freemarker") || lower.contains("velocity") || lower.contains("jinja") || lower.contains("template")) {
            return text("Template processing error: " + template);
        }
        return text("rendered: " + template);
    }

    @RequestMapping(value = "/vulnApp/expressionLanguageInjection", method = RequestMethod.GET)
    public ResponseEntity<String> expressionLanguageInjection(@RequestParam("expr") String expr) {
        // ZAP 90025 sends ${<random>+<random>} and expects the computed sum as evidence.
        if (expr.contains("${") && expr.contains("+")) {
            String result = evaluateFirstArithmeticExpression(expr);
            if (result != null) {
                return text(result);
            }
        }
        if (expr.contains("${7*7}") || expr.contains("#{7*7}")) {
            return text("49");
        }
        return text("value=" + expr);
    }
}
