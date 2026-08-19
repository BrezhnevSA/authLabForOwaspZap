var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpRequestHeader = Java.type(
    "org.parosproxy.paros.network.HttpRequestHeader"
);
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var System = Java.type("java.lang.System");
var ReentrantLock = Java.type("java.util.concurrent.locks.ReentrantLock");

// Нужны правки, URL для атаки (из интерфейса)
var API_URL = "http://script-token-check:3000";

// Нужны правки, реальный URL логина
var TOKEN_URL = "http://script-token-check:3000/api/login";

// Нужны правки, реальный логин
var USERNAME = "zapuser";

// Нужны правки, реальный пароль
var PASSWORD = "ZapTest123!";

// Нужны правки, время обновление токена
var TOKEN_CHECK_AFTER_SECONDS = 2;

// Нужны правки, URL для проверки
var TOKEN_CHECK_URL = API_URL + "/me";

// Возможно нужны правки, имя заголовка, который будет подставляться
var AUTH_HEADER = "Authorization";
// Возможно нужны правки, начало значения подставляемого заголовка (к нему приклеевается пробел и реальный токен)
var AUTH_PREFIX ="Bearer";

var INTERNAL_AUTH_HEADER = "X-ZAP-Internal-Token-Check";
var CHECK_AT_IN_MS_KEY = "check_at";
var SCRIPT_NAME = this["zap.script.name"] || "token-refresh";
var SCRIPT_CONTEXT = this.context;
var TOKEN_KEY = "token";

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
    var checkAt = Number(
        ScriptVars.getScriptVar(SCRIPT_CONTEXT, CHECK_AT_IN_MS_KEY)
    );
    return token && isFinite(checkAt) && Date.now() < checkAt;
}

function scheduleNextTokenCheck() {
    ScriptVars.setScriptVar(
        SCRIPT_CONTEXT,
        CHECK_AT_IN_MS_KEY,
        String(Date.now() + TOKEN_CHECK_AFTER_SECONDS * 1000)
    );
}

function isInternalAuthRequest(msg) {
    return msg.getRequestHeader().getHeader(INTERNAL_AUTH_HEADER) === "1";
}

function authorizationValue(token) {
    return AUTH_PREFIX.length === 0
        ? token
        : AUTH_PREFIX + " " + token;
}

function checkExistingToken(helper, token) {
    // Возможно нужны правки, если проверка авторизации как-то по-другому делается
    // здесь же обычный GET запрос /me, с передачей хедера с токеном
    try {
        var uri = new URI(TOKEN_CHECK_URL, false);
        var header = new HttpRequestHeader(
            HttpRequestHeader.GET,
            uri,
            HttpHeader.HTTP11
        );
        header.setHeader("Accept", "application/json");
        header.setHeader(INTERNAL_AUTH_HEADER, "1");
        header.setHeader(AUTH_HEADER, authorizationValue(token));
        var message = new HttpMessage(header);
        helper.getHttpSender().sendAndReceive(message, false);
        var status = message.getResponseHeader().getStatusCode();
        log("Token check HTTP " + status);
        if (status >= 200 && status < 300) {
            return "valid";
        }
        return status === 401 ? "expired" : "unknown";
    } catch (error) {
        log("Token check failed: " + error);
        return "unknown";
    }
}

function clearToken() {
    ScriptVars.setScriptVar(SCRIPT_CONTEXT, TOKEN_KEY, null);
    ScriptVars.setScriptVar(SCRIPT_CONTEXT, CHECK_AT_IN_MS_KEY, null);
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
        var currentToken = cachedToken();
        if (currentToken) {
            var checkResult = checkExistingToken(helper, currentToken);
            if (checkResult === "valid") {
                scheduleNextTokenCheck();
                return true;
            }
            if (checkResult === "unknown") {
                log("Token check is inconclusive; keeping cached token");
                scheduleNextTokenCheck();
                return true;
            }
            clearToken();
        }
        var loginMessage = createTokenRequest();
        // лог только для отладки
        //log("Requesting testbed token: " + TOKEN_URL);
        helper.getHttpSender().sendAndReceive(loginMessage, false);
        // лог только для отладки
        //log("Testbed login HTTP " + loginMessage.getResponseHeader().getStatusCode());
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
        scheduleNextTokenCheck();
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
    //log("URL=" + requestUrl(msg) + "; isManagedRequest=" + isManagedRequest(msg) + "; isTokenRequest=" + isTokenRequest(msg));
    if (
        isInternalAuthRequest(msg)
            || isTokenRequest(msg)
            || !isManagedRequest(msg)
    ) {
        return;
    }
    if (!refreshToken(helper)) {
        return;
    }

    var token = cachedToken();
    msg.getRequestHeader().setHeader(AUTH_HEADER, authorizationValue(token));
}

function responseReceived(msg, initiator, helper) {}