package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.html;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Extra deliberately vulnerable fixtures used to cover required ZAP alert classes which are
 * passive/client-side or need a very specific baseline response.
 *
 * <p>The fixtures emulate vulnerable behaviour without introducing a real server-side gadget
 * chain or executing attacker supplied commands.
 */
@RestController
public class RequiredCoverageAlertsController {

    /**
     * Expected: 90002 Java Serialized Object (maps to Insecure Serialization / CWE-502).
     *
     * <p>The passive rule looks for the Java serialization stream magic AC ED 00 05 at the start
     * of a request/response body (or rO0AB in base64 form).
     */
    @RequestMapping(value = "/vulnApp/passive/javaSerializedObject", method = RequestMethod.GET)
    public ResponseEntity<byte[]> javaSerializedObject() {
        byte[] serializedMarker = new byte[] {
            (byte) 0xac, (byte) 0xed, 0x00, 0x05,
            0x74, 0x00, 0x0c,
            'v', 'u', 'l', 'n', 'A', 'p', 'p', '-', 'd', 'e', 'm', 'o'
        };
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType("application/x-java-serialized-object"))
            .body(serializedMarker);
    }

    /** Expected: 10023 Information Disclosure - Debug Error Messages. */
    @RequestMapping(value = "/vulnApp/passive/debugErrorMessage", method = RequestMethod.GET)
    public ResponseEntity<String> debugErrorMessage() {
        return text(
            "Microsoft OLE DB Provider for SQL Server error '80040e14'\n"
                + "Incorrect syntax near 'zap'.\n"
                + "at System.Data.SqlClient.SqlCommand.ExecuteReader()"
        );
    }

    /**
     * Expected: 10024 Information Disclosure - Sensitive Information in URL.
     * The e-mail address is intentionally accepted in the query string so the passive request
     * scanner has deterministic evidence.
     */
    @RequestMapping(value = "/vulnApp/passive/sensitiveUrl", method = RequestMethod.GET)
    public ResponseEntity<String> sensitiveUrl(@RequestParam("email") String email) {
        return html("<html><body>Account lookup for " + email + "</body></html>");
    }

    /** Expected: 10027 Information Disclosure - Suspicious Comments. */
    @RequestMapping(value = "/vulnApp/passive/suspiciousComments", method = RequestMethod.GET)
    public ResponseEntity<String> suspiciousComments() {
        return html(
            "<html><body>"
                + "<!-- TODO: remove the temporary admin password before production -->"
                + "<!-- FIXME: debug endpoint /internal/admin is still enabled -->"
                + "<h1>Production portal</h1>"
                + "</body></html>"
        );
    }

    /**
     * Browser/client-side prototype pollution fixture.
     *
     * <p>Expected with the OWASP PTK beta integration: 210008-2 (tainted dangerous key used in a
     * prototype write) and 210008-1 (polluted prototype field inherited by fetch init).
     *
     * <p>Why the code looks like this (checked against PTK's content/iast.js):
     * <ul>
     *   <li>PTK only sees prototype writes made through Object.assign, Reflect.set and
     *       Object.defineProperty. A plain {@code obj[key] = value} is invisible to it, so the
     *       recursive merge writes every property through Reflect.set.</li>
     *   <li>Reflect.set is called with an explicit receiver (4th argument): PTK's wrapper
     *       forwards a missing receiver as {@code undefined}, which makes 3-argument calls throw or
     *       silently do nothing.</li>
     *   <li>PTK receives its rule pack asynchronously and installs the prototype hooks only after
     *       that, so a single run while the HTML is still being parsed can happen before the hooks
     *       exist. The merge therefore runs right away and then repeats every 250 ms (20 runs at
     *       most, never overlapping). Whatever time the crawler spends on the page, a run lands
     *       after the hooks are in place. A single run delayed by a timer is worse: a crawler that
     *       leaves the page right after the load event never reaches it.</li>
     *   <li>Each run requests {@code prototypePollutionEcho?run=N}; the highest N in the request log
     *       shows how long the crawler actually stayed on the page.</li>
     *   <li>The taint comes from the URL query (key/prop/value), so the scanner must open the page
     *       with its query string, e.g. ?key=__proto__&amp;prop=headers&amp;value=ptk-polluted.</li>
     * </ul>
     */
    @RequestMapping(value = "/vulnApp/prototypePollution", method = RequestMethod.GET)
    public ResponseEntity<String> prototypePollution(
        @RequestParam(value = "key", required = false) String ignoredKey,
        @RequestParam(value = "prop", required = false) String ignoredProp,
        @RequestParam(value = "value", required = false) String ignoredValue
    ) {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(
                "<!doctype html><html><head><title>Prototype Pollution Lab</title></head><body>"
                    + "<h1>Prototype Pollution Lab</h1><div id='result'></div>"
                    + "<script>"
                    + "(function(){"
                    + "var q=new URLSearchParams(window.location.search);"
                    + "var dangerousKey=q.get('key')||'__proto__';"
                    + "var pollutedProp=q.get('prop')||'headers';"
                    + "var taintedValue=q.get('value')||'ptk-polluted';"
                    + "function isObj(v){return v!==null&&typeof v==='object';}"
                    // Classic vulnerable recursive merge: follows the attacker-controlled "__proto__"
                    // key into Object.prototype. Every write goes through Reflect.set (PTK-visible).
                    + "function unsafeMerge(target,source){"
                    + "Object.keys(source).forEach(function(k){"
                    + "var v=source[k];"
                    + "Reflect.set(target,k,isObj(v)?unsafeMerge(isObj(target[k])?target[k]:{},v):v,target);"
                    + "});"
                    + "return target;}"
                    + "var runs=0,busy=false;"
                    + "function run(){"
                    // Never overlap: a second run would snapshot the already polluted prototype.
                    + "if(busy)return;busy=true;runs++;"
                    + "var polluted=(pollutedProp==='headers')?{'X-PTK-Polluted':taintedValue}:taintedValue;"
                    // JSON.parse creates an OWN "__proto__" property (an object literal would not).
                    + "var patch=JSON.parse('{'+JSON.stringify(dangerousKey)+':{'+JSON.stringify(pollutedProp)+':'+JSON.stringify(polluted)+'}}');"
                    + "var had=Object.prototype.hasOwnProperty.call(Object.prototype,pollutedProp);"
                    + "var old=Object.prototype[pollutedProp];"
                    + "unsafeMerge({},patch);"
                    // 210008-1: fetch() reads the polluted "headers" from its init object.
                    + "fetch('prototypePollutionEcho?run='+runs,{})"
                    + ".then(function(r){return r.text();})"
                    + ".then(function(t){document.getElementById('result').textContent=t+' inherited='+String(({})[pollutedProp])+' runs='+runs;})"
                    + ".catch(function(e){document.getElementById('result').textContent='fetch error '+String(e);})"
                    // Undo the pollution once the request has settled so the lab does not leak state.
                    + ".finally(function(){try{if(had){Object.prototype[pollutedProp]=old;}else{delete Object.prototype[pollutedProp];}}catch(e){}busy=false;});"
                    + "}"
                    + "run();"
                    + "var timer=setInterval(function(){if(runs>=20){clearInterval(timer);return;}run();},250);"
                    + "})();"
                    + "</script></body></html>"
            );
    }

    @RequestMapping(value = "/vulnApp/prototypePollutionEcho", method = RequestMethod.GET)
    public ResponseEntity<String> prototypePollutionEcho() {
        return json("{\"status\":\"ok\"}");
    }
}
