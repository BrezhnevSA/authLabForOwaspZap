var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpRequestHeader = Java.type(
    "org.parosproxy.paros.network.HttpRequestHeader"
);
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var System = Java.type("java.lang.System");
var ReentrantLock = Java.type("java.util.concurrent.locks.ReentrantLock");
var Base64 = Java.type("java.util.Base64");
var StandardCharsets = Java.type("java.nio.charset.StandardCharsets");
var JavaString = Java.type("java.lang.String");

// Нужны правки, URL для атаки (из интерфейса)
var API_URL = "http://script-jwt-exp:3000";

// Нужны правки, реальный URL логина
var TOKEN_URL = "http://script-jwt-exp:3000/api/login";

// Нужны правки, реальный логин
var USERNAME = "zapuser";

// Нужны правки, реальный пароль
var PASSWORD = "ZapTest123!";

var AUTH_HEADER = "Authorization";
var AUTH_PREFIX ="Bearer";
// Возможно нужны правки, если токен протухает быстрее\медленее и его не получается прочитать время протухания из токена
var FALLBACK_TTL_SECONDS = 15;
var REFRESH_SKEW_MS = 2 * 1000;

var SCRIPT_NAME = this["zap.script.name"] || "token-refresh";
var SCRIPT_CONTEXT = this.context;
var TOKEN_KEY = "token";
var EXPIRY_IN_MS_KEY = "expiry";

var refreshLock = new ReentrantLock();

function log(message) {
    print("[" + SCRIPT_NAME + "] " + message);
}

function requestUrl(msg) {
    return String(msg.getRequestHeader().getURI().toString());
}

function isTokenRequest(msg) {
    return requestUrl(msg).indexOf(TOKEN_URL) === 0;
}

function isManagedRequest(msg) {
    var url = requestUrl(msg);
    return url === API_URL || url.indexOf(API_URL + "/") === 0;
}

function cachedToken() {
    return ScriptVars.getScriptVar(SCRIPT_CONTEXT, TOKEN_KEY);
}

function tokenIsValid() {
    var token = cachedToken();
    var expiresAt = Number(ScriptVars.getScriptVar(SCRIPT_CONTEXT, EXPIRY_IN_MS_KEY));
    return token && isFinite(expiresAt) && Date.now() < expiresAt - REFRESH_SKEW_MS;
}

function clearToken() {
    ScriptVars.setScriptVar(SCRIPT_CONTEXT, TOKEN_KEY, null);
    ScriptVars.setScriptVar(SCRIPT_CONTEXT, EXPIRY_IN_MS_KEY, null);
}

function tokenExpiresAt(payload, token) {
    try {
        var encodedClaims = String(token).split(".")[1];
        var claimsJson = new JavaString(
            Base64.getUrlDecoder().decode(encodedClaims),
            StandardCharsets.UTF_8
        );
        var exp = Number(JSON.parse(String(claimsJson)).exp);

        if (isFinite(exp) && exp > 0) {
            return exp * 1000;
        }
    } catch (error) {
        log("Could not read JWT expiry: " + error);
    }

    return Date.now() + FALLBACK_TTL_SECONDS * 1000;
}

function createTokenRequest() {
    // Возможно нужны правки, если авторизация как-то по-другому делается
    // здесь же обычный POST запрос логина, с передачей пароля и логина в боди
    var uri = new URI(TOKEN_URL, false);
    var header = new HttpRequestHeader(
        HttpRequestHeader.POST,
        uri,
        HttpHeader.HTTP11
    );
    header.setHeader("Content-Type", "application/json; charset=UTF-8");
    header.setHeader("Accept", "application/json");
    var message = new HttpMessage(header);
    message.setRequestBody(
    	JSON.stringify({
        	username: USERNAME,
        	password: PASSWORD
    	})
	);
    message.getRequestHeader().setHeader("Content-Length", String(message.getRequestBody().length()));
    return message;
}

function refreshToken(helper) {
    if (tokenIsValid()) {
        return true;
    }
    refreshLock.lock();
    try {
        if (tokenIsValid()) {
            return true;
        }
        var loginMessage = createTokenRequest();
		// лог только для отладки
        log("Requesting testbed token: " + TOKEN_URL);
        helper.getHttpSender().sendAndReceive(loginMessage, false);
		// лог только для отладки
		log("Testbed login HTTP " + loginMessage.getResponseHeader().getStatusCode());
        var status = loginMessage.getResponseHeader().getStatusCode();
        if (status < 200 || status >= 300) {
            log("Token endpoint returned HTTP " + status);
            clearToken();
            return false;
        }
        var payload = JSON.parse(String(loginMessage.getResponseBody()));
        // Возможно нужны правки, надо вытащить токен из ответа
        // проверка, что авторизация успешная
        if (payload.status !== "success" || !payload.auth_token) {
		    log("VAmPI login failed: " + (payload.message || "no auth_token"));
		    clearToken();
		    return false;
		}
		// вытаскивание токена из ответа
		var token = payload.auth_token;
        if (!token) {
            log("No access token in token-endpoint response");
            clearToken();
            return false;
        }
		ScriptVars.setScriptVar(SCRIPT_CONTEXT, TOKEN_KEY, String(token));
		ScriptVars.setScriptVar( SCRIPT_CONTEXT, EXPIRY_IN_MS_KEY, String(tokenExpiresAt(payload, token)));
        log("Token refreshed");
        return true;
    } catch (error) {
        log("Token refresh failed: " + error);
        clearToken();
        return false;
    } finally {
        refreshLock.unlock();
    }
}

function sendingRequest(msg, initiator, helper) {
	// лог только для отладки
	log("URL=" + requestUrl(msg) + "; isManagedRequest=" + isManagedRequest(msg) + "; isTokenRequest=" + isTokenRequest(msg));
    if (isTokenRequest(msg) || !isManagedRequest(msg)) {
        return;
    }
    if (!refreshToken(helper)) {
        return;
    }
    var value = cachedToken();
    var authorization = AUTH_PREFIX.length === 0
        ? value
        : AUTH_PREFIX + " " + value;
    msg.getRequestHeader().setHeader(AUTH_HEADER, authorization);
}

function responseReceived(msg, initiator, helper) {}