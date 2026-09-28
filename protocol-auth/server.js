const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const PORT = Number(process.env.PORT || 3000), SCENARIO = process.env.SCENARIO || 'basic';
const USERNAME='zapuser', PASSWORD='ZapTest123!', BEARER='zap-bearer-token-2026', API_KEY='zap-api-key-2026', CLIENT_ID='zap-client', CLIENT_SECRET='zap-client-secret-2026', REALM='ZAP-AUTH-LAB';
const CONTROL_TOKEN=process.env.TESTBED_CONTROL_TOKEN||'zap-testbed-reset-v1';
const NONCE=crypto.randomBytes(18).toString('hex'); const sessions=new Map();
const full=SCENARIO==='basic-form'; const EXPECTED=full?['/private','/api/profile','/api/orders','/api/documents']:['/private'];
const hits=new Map(); const auth={challenges:0,loginAttempts:0,successfulLogins:0,failedLogins:0,authenticatedRequests:0,unauthorizedRequests:0};
function send(res,s,b,h={}){res.writeHead(s,{'Content-Type':'application/json; charset=utf-8',...h});res.end(JSON.stringify(b))}
function html(res,s,b,h={}){res.writeHead(s,{'Content-Type':'text/html; charset=utf-8',...h});res.end(`<!doctype html><html><body style="font-family:sans-serif;max-width:720px;margin:48px auto">${b}</body></html>`)}
function parseBasic(v){if(!v?.startsWith('Basic '))return null;try{const s=Buffer.from(v.slice(6),'base64').toString('utf8'),i=s.indexOf(':');return i<0?null:[s.slice(0,i),s.slice(i+1)]}catch{return null}}
function md5(s){return crypto.createHash('md5').update(s).digest('hex')}
function parseDigest(h){if(!h?.startsWith('Digest '))return null;const o={};for(const m of h.slice(7).matchAll(/(\w+)=((?:"[^"]*")|[^,]+)/g))o[m[1]]=m[2].replace(/^"|"$/g,'');return o}
function verifyDigest(req){const d=parseDigest(req.headers.authorization);if(!d||d.username!==USERNAME||d.realm!==REALM||d.nonce!==NONCE)return false;const ha1=md5(`${USERNAME}:${REALM}:${PASSWORD}`),uri=d.uri||req.url,ha2=md5(`${req.method}:${uri}`);const exp=d.qop?md5(`${ha1}:${NONCE}:${d.nc}:${d.cnonce}:${d.qop}:${ha2}`):md5(`${ha1}:${NONCE}:${ha2}`);return exp===d.response}
function cookie(req,n){for(const p of(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0&&p.slice(0,i).trim()===n)return decodeURIComponent(p.slice(i+1).trim())}return null}
function newSession(){const id=crypto.randomUUID();sessions.set(id,USERNAME);return id}
function readBody(req){return new Promise((ok,fail)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>ok(Object.fromEntries(new URLSearchParams(b))));req.on('error',fail)})}
function track(p){if(EXPECTED.includes(p))hits.set(p,(hits.get(p)||0)+1)}
function coverage(){const v=EXPECTED.filter(p=>hits.has(p));return {application:SCENARIO==='basic-form'?'basic-then-form':SCENARIO,scenario:SCENARIO,discovery:{expected:EXPECTED.length,visited:v.length,coveragePercent:Number((v.length*100/EXPECTED.length).toFixed(2)),visitedEndpoints:v,missingEndpoints:EXPECTED.filter(p=>!hits.has(p))},authentication:{...auth,activeSessions:sessions.size}}}
function reset(){hits.clear();sessions.clear();Object.keys(auth).forEach(k=>auth[k]=0)}
function challenge(res,body,h){auth.challenges++;auth.unauthorizedRequests++;return send(res,401,body,h)}
async function handler(req,res){const url=new URL(req.url,`http://${req.headers.host||'localhost'}`),p=url.pathname;
 if(p==='/health')return send(res,200,{ok:true,scenario:SCENARIO});
 if(p==='/__testbed/expected'&&req.method==='GET')return send(res,200,{application:SCENARIO,expectedEndpoints:EXPECTED});
 if(p==='/__testbed/coverage'&&req.method==='GET')return send(res,200,coverage());
 if(p==='/__testbed/control/reset'&&req.method==='POST'){if(req.headers['x-testbed-control']!==CONTROL_TOKEN)return send(res,404,{error:'not found'});reset();return send(res,200,{reset:true,application:SCENARIO})}
 let authenticated=false,method=SCENARIO;
 if(SCENARIO==='basic'){const c=parseBasic(req.headers.authorization);authenticated=!!c&&c[0]===USERNAME&&c[1]===PASSWORD;if(!authenticated)return challenge(res,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':`Basic realm="${REALM}"`})}
 else if(SCENARIO==='digest'){authenticated=verifyDigest(req);if(!authenticated)return challenge(res,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':`Digest realm="${REALM}", nonce="${NONCE}", algorithm=MD5, qop="auth"`})}
 else if(SCENARIO==='bearer'){authenticated=req.headers.authorization===`Bearer ${BEARER}`;if(!authenticated)return challenge(res,{authenticated:false,scenario:SCENARIO},{'WWW-Authenticate':'Bearer realm="ZAP-AUTH-LAB"'})}
 else if(SCENARIO==='api-key'){authenticated=req.headers['x-api-key']===API_KEY;if(!authenticated)return challenge(res,{authenticated:false,scenario:SCENARIO,error:'X-API-Key required'})}
 else if(SCENARIO==='multi-header'){authenticated=req.headers['x-client-id']===CLIENT_ID&&req.headers['x-client-secret']===CLIENT_SECRET;if(!authenticated)return challenge(res,{authenticated:false,scenario:SCENARIO,error:'X-Client-Id and X-Client-Secret required'})}
 else if(SCENARIO==='basic-form'){const c=parseBasic(req.headers.authorization),basicOk=!!c&&c[0]===USERNAME&&c[1]===PASSWORD;if(!basicOk)return challenge(res,{authenticated:false,stage:'basic'},{'WWW-Authenticate':`Basic realm="${REALM}"`});if(req.method==='GET'&&(p==='/'||p==='/login')){if(sessions.has(cookie(req,'stack_sid')))return html(res,200,'<h1>AUTHENTICATED</h1><a href="/private">private</a>');return html(res,200,'<h1>Stage 2: form login</h1><form method="post" action="/login"><label>Username <input name="username" autocomplete="username"></label><br><label>Password <input type="password" name="password" autocomplete="current-password"></label><br><button>Sign in</button></form>')}
  if(req.method==='POST'&&p==='/login'){auth.loginAttempts++;const f=await readBody(req);if(f.username===USERNAME&&f.password===PASSWORD){auth.successfulLogins++;const sid=newSession();res.writeHead(302,{Location:'/private','Set-Cookie':`stack_sid=${sid}; Path=/; HttpOnly`});return res.end()}auth.failedLogins++;return html(res,401,'<h1>Form credentials rejected</h1>')}
  authenticated=sessions.has(cookie(req,'stack_sid'));if(!authenticated)return challenge(res,{authenticated:false,stage:'form'});method='basic+form'}
 auth.authenticatedRequests++;
 if(p==='/api/whoami')return send(res,200,{authenticated:true,username:USERNAME,scenario:SCENARIO,authType:method});
 if(p==='/private'||p==='/'){track('/private');if(full)return html(res,200,'<h1>AUTHENTICATED</h1><ul><li><a href="/api/profile">profile</a></li><li><a href="/api/orders">orders</a></li><li><a href="/api/documents">documents</a></li></ul>');return send(res,200,{authenticated:true,username:USERNAME,scenario:SCENARIO,authType:method,secret:'protected'})}
 if(full&&['/api/profile','/api/orders','/api/documents'].includes(p)){track(p);return send(res,200,{authenticated:true,endpoint:p,scenario:SCENARIO})}
 return send(res,404,{error:'not found',scenario:SCENARIO})}
http.createServer((q,s)=>handler(q,s).catch(e=>{console.error(e);send(s,500,{error:'internal'})})).listen(PORT,'0.0.0.0',()=>console.log(`${SCENARIO} on ${PORT}`));
