const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const SCENARIO = process.env.SCENARIO || 'basic';
const USERNAME = 'zapuser';
const PASSWORD = 'ZapTest123!';
const BEARER = 'zap-bearer-token-2026';
const API_KEY = 'zap-api-key-2026';
const CLIENT_ID = 'zap-client';
const CLIENT_SECRET = 'zap-client-secret-2026';
const REALM = 'ZAP-AUTH-LAB';
const NONCE = crypto.randomBytes(18).toString('hex');
const sessions = new Map();

function send(res,status,body,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8',...headers});res.end(JSON.stringify(body));}
function html(res,status,body,headers={}){res.writeHead(status,{'Content-Type':'text/html; charset=utf-8',...headers});res.end(`<!doctype html><html><body style="font-family:sans-serif;max-width:720px;margin:48px auto">${body}</body></html>`)}
function parseBasic(value){if(!value?.startsWith('Basic '))return null;try{const s=Buffer.from(value.slice(6),'base64').toString('utf8');const i=s.indexOf(':');return i<0?null:[s.slice(0,i),s.slice(i+1)];}catch{return null}}
function md5(s){return crypto.createHash('md5').update(s).digest('hex')}
function parseDigest(h){if(!h?.startsWith('Digest '))return null;const o={};for(const m of h.slice(7).matchAll(/(\w+)=((?:"[^"]*")|[^,]+)/g)){o[m[1]]=m[2].replace(/^"|"$/g,'');}return o}
function verifyDigest(req){const d=parseDigest(req.headers.authorization);if(!d||d.username!==USERNAME||d.realm!==REALM||d.nonce!==NONCE)return false;const ha1=md5(`${USERNAME}:${REALM}:${PASSWORD}`);const uri=d.uri||req.url;const ha2=md5(`${req.method}:${uri}`);let exp;if(d.qop){exp=md5(`${ha1}:${NONCE}:${d.nc}:${d.cnonce}:${d.qop}:${ha2}`)}else{exp=md5(`${ha1}:${NONCE}:${ha2}`)}return exp===d.response}
function cookie(req,name){for(const p of (req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0&&p.slice(0,i).trim()===name)return decodeURIComponent(p.slice(i+1).trim())}return null}
function newSession(){const id=crypto.randomUUID();sessions.set(id,USERNAME);return id}
function readBody(req){return new Promise((ok,fail)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>ok(Object.fromEntries(new URLSearchParams(b))));req.on('error',fail)})}

async function handler(req,res){
 const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
 if(url.pathname==='/health')return send(res,200,{ok:true,scenario:SCENARIO});
 let authenticated=false, method=SCENARIO;
 if(SCENARIO==='basic'){
   const c=parseBasic(req.headers.authorization);authenticated=!!c&&c[0]===USERNAME&&c[1]===PASSWORD;
   if(!authenticated)return send(res,401,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':`Basic realm="${REALM}"`});
 } else if(SCENARIO==='digest'){
   authenticated=verifyDigest(req);
   if(!authenticated)return send(res,401,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':`Digest realm="${REALM}", nonce="${NONCE}", algorithm=MD5, qop="auth"`});
 } else if(SCENARIO==='bearer'){
   authenticated=req.headers.authorization===`Bearer ${BEARER}`;
   if(!authenticated)return send(res,401,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':'Bearer realm="ZAP-AUTH-LAB"'});
 } else if(SCENARIO==='api-key'){
   authenticated=req.headers['x-api-key']===API_KEY;
   if(!authenticated)return send(res,401,{authenticated:false,scenario:SCENARIO,error:'X-API-Key required'});
 } else if(SCENARIO==='multi-header'){
   authenticated=req.headers['x-client-id']===CLIENT_ID&&req.headers['x-client-secret']===CLIENT_SECRET;
   if(!authenticated)return send(res,401,{authenticated:false,scenario:SCENARIO,error:'X-Client-Id and X-Client-Secret required'});
 } else if(SCENARIO==='basic-form'){
   const c=parseBasic(req.headers.authorization);const basicOk=!!c&&c[0]===USERNAME&&c[1]===PASSWORD;
   if(!basicOk)return send(res,401,{authenticated:false,stage:'basic'},{'WWW-Authenticate':`Basic realm="${REALM}"`});
   if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/login')){
     if(sessions.has(cookie(req,'stack_sid')))return html(res,200,'<h1>AUTHENTICATED</h1><a href="/api/whoami">whoami</a>');
     return html(res,200,'<h1>Stage 2: form login</h1><form method="post" action="/login"><label>Username <input name="username" autocomplete="username"></label><br><label>Password <input type="password" name="password" autocomplete="current-password"></label><br><button>Sign in</button></form>');
   }
   if(req.method==='POST'&&url.pathname==='/login'){
     const f=await readBody(req);if(f.username===USERNAME&&f.password===PASSWORD){const sid=newSession();res.writeHead(302,{Location:'/private','Set-Cookie':`stack_sid=${sid}; Path=/; HttpOnly`});return res.end();}return html(res,401,'<h1>Form credentials rejected</h1>');
   }
   authenticated=sessions.has(cookie(req,'stack_sid'));
   if(!authenticated)return send(res,401,{authenticated:false,stage:'form'});
   method='basic+form';
 }
 if(url.pathname==='/api/whoami')return send(res,200,{authenticated:true,username:USERNAME,scenario:SCENARIO,authType:method});
 if(url.pathname==='/private'||url.pathname==='/')return send(res,200,{authenticated:true,username:USERNAME,scenario:SCENARIO,authType:method,secret:'protected'});
 return send(res,404,{error:'not found',scenario:SCENARIO});
}
http.createServer((req,res)=>handler(req,res).catch(e=>{console.error(e);send(res,500,{error:'internal'})})).listen(PORT,'0.0.0.0',()=>console.log(`${SCENARIO} on ${PORT}`));
