const http=require('http');const crypto=require('crypto');const {URL}=require('url');
const PORT=Number(process.env.PORT||3000), SCENARIO=process.env.SCENARIO||'modal-login';
const USERNAME='zapuser',PASSWORD='ZapTest123!',JWT='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXB1c2VyIiwic2NvcGUiOiJzY2FuIn0.';
const sessions=new Map();
function html(res,s,b,h={}){res.writeHead(s,{'Content-Type':'text/html; charset=utf-8',...h});res.end(`<!doctype html><html><head><meta charset="utf-8"><style>body{font-family:sans-serif;max-width:760px;margin:48px auto}#modal{border:1px solid #777;padding:20px;margin-top:20px}label{display:block;margin:10px}</style></head><body>${b}</body></html>`)}
function json(res,s,o,h={}){res.writeHead(s,{'Content-Type':'application/json; charset=utf-8',...h});res.end(JSON.stringify(o))}
function redir(res,l,h={}){res.writeHead(302,{Location:l,...h});res.end()}
function cookie(req,n){for(const p of(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0&&p.slice(0,i).trim()===n)return decodeURIComponent(p.slice(i+1).trim())}return null}
function read(req){return new Promise((ok,fail)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{if((req.headers['content-type']||'').includes('json')){try{return ok(JSON.parse(b||'{}'))}catch{return ok({})}}ok(Object.fromEntries(new URLSearchParams(b)))});req.on('error',fail)})}
function setSession(user=USERNAME){const s=crypto.randomUUID();sessions.set(s,user);return {'Set-Cookie':`flow_sid=${s}; Path=/; HttpOnly; SameSite=Lax`}}
function who(req){return sessions.get(cookie(req,'flow_sid'))||null}
function form(action='/login',extra=''){return `<form method="post" action="${action}"><label>Username <input name="username" autocomplete="username"></label><label>Password <input type="password" name="password" autocomplete="current-password"></label>${extra}<button>Sign in</button></form>`}
async function handle(req,res){const u=new URL(req.url,`http://${req.headers.host||'localhost'}`),p=u.pathname;
 if(p==='/health')return json(res,200,{ok:true,scenario:SCENARIO});
 if(SCENARIO==='modal-login'){
  if(req.method==='GET'&&(p==='/'||p==='/login'))return html(res,200,`<h1>Public page</h1><button id="open">Sign in</button><div id="root"></div><script>document.getElementById('open').onclick=()=>document.getElementById('root').innerHTML=${JSON.stringify('<div id="modal"><h2>Login modal</h2>'+form('/login')+'</div>')}</script>`);
  if(req.method==='POST'&&p==='/login'){const f=await read(req);if(f.username===USERNAME&&f.password===PASSWORD)return redir(res,'/private',setSession());return html(res,401,'bad credentials')}
 }
 if(SCENARIO==='consent-checkbox'){
  if(req.method==='GET'&&(p==='/'||p==='/login'))return html(res,200,`<h1>Consent required</h1><form id="f"><label>Username <input id="u" autocomplete="username"></label><label>Password <input id="pw" type="password" autocomplete="current-password"></label><label><input id="consent" type="checkbox"> I accept the security notice</label><button>Sign in</button></form><p id="m"></p><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const c=document.getElementById('consent'),m=document.getElementById('m');if(!c.checked){m.textContent='Consent required';return}const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('pw').value,consent:true})});if(r.ok)location='/private';else m.textContent='Login failed'}</script>`);
  if(req.method==='POST'&&p==='/api/login'){const f=await read(req);if(f.username===USERNAME&&f.password===PASSWORD&&f.consent===true)return json(res,200,{ok:true},setSession());return json(res,401,{ok:false})}
 }
 if(SCENARIO==='localstorage-jwt'){
  if(req.method==='GET'&&(p==='/'||p==='/login'))return html(res,200,`<h1>JWT in localStorage</h1><form id="f"><label>Username <input id="u" autocomplete="username"></label><label>Password <input id="pw" type="password" autocomplete="current-password"></label><button>Sign in</button></form><pre id="out"></pre><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('pw').value})});if(!r.ok)return;const x=await r.json();localStorage.setItem('access_token',x.access_token);location='/dashboard'}</script>`);
  if(req.method==='POST'&&p==='/api/login'){const f=await read(req);if(f.username===USERNAME&&f.password===PASSWORD)return json(res,200,{access_token:JWT,token_type:'Bearer'});return json(res,401,{})}
  if(req.method==='GET'&&p==='/dashboard')return html(res,200,`<h1>Dashboard</h1><pre id="x">loading...</pre><script>fetch('/api/whoami',{headers:{Authorization:'Bearer '+localStorage.getItem('access_token')}}).then(r=>r.json()).then(v=>document.getElementById('x').textContent=JSON.stringify(v,null,2))</script>`);
  if((p==='/api/whoami'||p==='/private')&&req.headers.authorization===`Bearer ${JWT}`)return json(res,200,{authenticated:true,username:USERNAME,scenario:SCENARIO,authType:'bearer-from-localStorage'});
  if(p==='/api/whoami'||p==='/private')return json(res,401,{authenticated:false,scenario:SCENARIO});
 }
 if(SCENARIO==='sso-app'||SCENARIO==='cross-domain-app'){
  const idp=process.env.IDP_URL;
  if(req.method==='GET'&&(p==='/'||p==='/login')){const state=crypto.randomUUID();sessions.set('state:'+state,'pending');return redir(res,`${idp}/authorize?client_id=zap-app&redirect_uri=${encodeURIComponent(process.env.CALLBACK_URL)}&state=${encodeURIComponent(state)}`)}
  if(req.method==='GET'&&p==='/callback'){const code=u.searchParams.get('code'),state=u.searchParams.get('state');if(sessions.get('state:'+state)!=='pending'||code!==`zap-code-${state}`)return html(res,400,'invalid state/code');sessions.delete('state:'+state);return redir(res,'/private',setSession())}
 }
 if(SCENARIO==='sso-idp'||SCENARIO==='cross-domain-idp'){
  if(req.method==='GET'&&p==='/authorize'){const q=Object.fromEntries(u.searchParams);return html(res,200,`<h1>Test IdP</h1>${form('/authorize',`<input type="hidden" name="client_id" value="${q.client_id||''}"><input type="hidden" name="redirect_uri" value="${q.redirect_uri||''}"><input type="hidden" name="state" value="${q.state||''}">`)}`)}
  if(req.method==='POST'&&p==='/authorize'){const f=await read(req);if(f.username!==USERNAME||f.password!==PASSWORD)return html(res,401,'IdP login failed');const c=`zap-code-${f.state}`;return redir(res,`${f.redirect_uri}?code=${encodeURIComponent(c)}&state=${encodeURIComponent(f.state)}`)}
 }
 const user=who(req);if(p==='/api/whoami')return json(res,user?200:401,user?{authenticated:true,username:user,scenario:SCENARIO}:{authenticated:false,scenario:SCENARIO});
 if(p==='/private')return user?html(res,200,`<h1>AUTHENTICATED</h1><p>${SCENARIO}</p>`):json(res,401,{authenticated:false,scenario:SCENARIO});
 return json(res,404,{error:'not found',scenario:SCENARIO});
}
http.createServer((q,s)=>handle(q,s).catch(e=>{console.error(e);json(s,500,{error:String(e)})})).listen(PORT,'0.0.0.0',()=>console.log(`${SCENARIO} ${PORT}`));
