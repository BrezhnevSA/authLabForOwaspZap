var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var ReentrantLock = Java.type("java.util.concurrent.locks.ReentrantLock");

var API_URL = "http://consent-checkbox:3000";
var USERNAME = "zapuser";
var PASSWORD = "ZapTest123!";
var INTERNAL_HEADER = "X-ZAP-Internal-Auth";
var SCRIPT_CONTEXT = this.context;
var SESSION_KEY = "session";
var refreshLock = new ReentrantLock();

var SCRIPT_NAME = this["zap.script.name"] || "script-auth";
function log(message) { print("[" + SCRIPT_NAME + "] " + message); }
function requestUrl(msg) { return String(msg.getRequestHeader().getURI().toString()); }
function isManagedRequest(msg) { var u=requestUrl(msg); return u===API_URL || u.indexOf(API_URL + "/")===0; }
function isInternal(msg) { return msg.getRequestHeader().getHeader(INTERNAL_HEADER)==="1"; }
function cachedSession() { return ScriptVars.getScriptVar(SCRIPT_CONTEXT, SESSION_KEY); }
function saveSession(value) { ScriptVars.setScriptVar(SCRIPT_CONTEXT, SESSION_KEY, value); }
function clearSession() { ScriptVars.setScriptVar(SCRIPT_CONTEXT, SESSION_KEY, null); }
function cookieFromResponse(message) {
    var value=message.getResponseHeader().getHeader("Set-Cookie");
    if (!value) return null;
    return String(value).split(";")[0];
}
function newMessage(method, url, contentType, body, cookie) {
    var header=new HttpRequestHeader(method, new URI(url, false), HttpHeader.HTTP11);
    header.setHeader("Accept", "*/*");
    header.setHeader(INTERNAL_HEADER, "1");
    if (contentType) header.setHeader("Content-Type", contentType);
    if (cookie) header.setHeader("Cookie", cookie);
    var message=new HttpMessage(header);
    if (body !== null && body !== undefined) {
        message.setRequestBody(String(body));
        message.getRequestHeader().setHeader("Content-Length", String(message.getRequestBody().length()));
    }
    return message;
}
function formEncode(value) { return encodeURIComponent(String(value)); }
function requireStatus(message, allowed) {
    var status=message.getResponseHeader().getStatusCode();
    for (var i=0;i<allowed.length;i++) if (status===allowed[i]) return true;
    log("Unexpected login HTTP " + status + " for " + requestUrl(message));
    return false;
}
function login(helper) {
    var body=JSON.stringify({username:USERNAME,password:PASSWORD,consent:true});
    var message=newMessage(HttpRequestHeader.POST, API_URL + "/api/login", "application/json; charset=UTF-8", body, null);
    helper.getHttpSender().sendAndReceive(message, false);
    if (!requireStatus(message,[200])) return null;
    return cookieFromResponse(message);
}

function ensureSession(helper) {
    if (cachedSession()) return true;
    refreshLock.lock();
    try {
        if (cachedSession()) return true;
        var session=login(helper);
        if (!session) { clearSession(); return false; }
        saveSession(String(session));
        log("Session acquired");
        return true;
    } catch (e) {
        log("Login failed: " + e);
        clearSession();
        return false;
    } finally { refreshLock.unlock(); }
}
function sendingRequest(msg, initiator, helper) {
    if (isInternal(msg) || !isManagedRequest(msg)) return;
    if (!ensureSession(helper)) return;
    msg.getRequestHeader().setHeader("Cookie", cachedSession());
}
function responseReceived(msg, initiator, helper) {
    if (!isManagedRequest(msg) || isInternal(msg)) return;
    if (msg.getResponseHeader().getStatusCode()===401) clearSession();
}
