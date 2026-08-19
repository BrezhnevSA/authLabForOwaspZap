var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var ReentrantLock = Java.type("java.util.concurrent.locks.ReentrantLock");
var API_URL="http://localstorage-jwt:3000";
var TOKEN_URL=API_URL + "/api/login";
var USERNAME="zapuser", PASSWORD="ZapTest123!";
var INTERNAL_HEADER="X-ZAP-Internal-Auth";
var SCRIPT_CONTEXT=this.context, TOKEN_KEY="token";
var lock=new ReentrantLock();
function requestUrl(msg){return String(msg.getRequestHeader().getURI().toString());}
function isManaged(msg){var u=requestUrl(msg);return u===API_URL||u.indexOf(API_URL+"/")===0;}
function token(){return ScriptVars.getScriptVar(SCRIPT_CONTEXT,TOKEN_KEY);}
function acquire(helper){
  if(token()) return true;
  lock.lock();
  try{
    if(token()) return true;
    var h=new HttpRequestHeader(HttpRequestHeader.POST,new URI(TOKEN_URL,false),HttpHeader.HTTP11);
    h.setHeader("Content-Type","application/json; charset=UTF-8");h.setHeader(INTERNAL_HEADER,"1");
    var m=new HttpMessage(h);m.setRequestBody(JSON.stringify({username:USERNAME,password:PASSWORD}));m.getRequestHeader().setHeader("Content-Length",String(m.getRequestBody().length()));
    helper.getHttpSender().sendAndReceive(m,false);
    if(m.getResponseHeader().getStatusCode()!==200)return false;
    var p=JSON.parse(String(m.getResponseBody()));if(!p.access_token)return false;
    ScriptVars.setScriptVar(SCRIPT_CONTEXT,TOKEN_KEY,String(p.access_token));return true;
  }finally{lock.unlock();}
}
function sendingRequest(msg,initiator,helper){if(msg.getRequestHeader().getHeader(INTERNAL_HEADER)==="1"||!isManaged(msg)||requestUrl(msg).indexOf(TOKEN_URL)===0)return;if(!acquire(helper))return;msg.getRequestHeader().setHeader("Authorization","Bearer "+token());}
function responseReceived(msg,initiator,helper){if(isManaged(msg)&&msg.getResponseHeader().getStatusCode()===401)ScriptVars.setScriptVar(SCRIPT_CONTEXT,TOKEN_KEY,null);}
