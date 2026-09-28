from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import secrets

app=FastAPI(); sessions={}
CONTROL_TOKEN='zap-testbed-reset-v1'
EXPECTED=['/private','/api/profile','/api/orders','/api/documents']
hits={}
auth={'loginAttempts':0,'successfulLogins':0,'failedLogins':0,'authenticatedRequests':0,'unauthorizedRequests':0}
PAGE="""<!doctype html><html><body><h1>FastAPI Dynamic Login</h1><p>The login controls are created only after JavaScript interaction.</p><button id="open">Sign in</button><div id="slot"></div><script>
document.getElementById('open').onclick=()=>{document.getElementById('slot').innerHTML=`<div id="modal"><label>Username <input id="u" name="username" autocomplete="username"></label><br><label>Password <input id="p" name="password" type="password" autocomplete="current-password"></label><br><button id="go">Login</button><p id="msg"></p></div>`;document.getElementById('go').onclick=async()=>{let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});if(r.ok)location='/private';else document.getElementById('msg').textContent='bad credentials';};};
</script></body></html>"""
def current(req): return sessions.get(req.cookies.get('sid',''))
def track(path):
    if path in EXPECTED: hits[path]=hits.get(path,0)+1
def cov():
    visited=[p for p in EXPECTED if p in hits]
    return {'application':'fastapi-dynamic','scenario':'dynamic-json-cookie','discovery':{'expected':len(EXPECTED),'visited':len(visited),'coveragePercent':round(len(visited)*100/len(EXPECTED),2),'visitedEndpoints':visited,'missingEndpoints':[p for p in EXPECTED if p not in hits]},'authentication':dict(auth)}
def mark(req,path):
    track(path); u=current(req)
    if u: auth['authenticatedRequests']+=1
    else: auth['unauthorizedRequests']+=1
    return u
@app.get('/__testbed/expected')
def expected(): return {'application':'fastapi-dynamic','expectedEndpoints':EXPECTED}
@app.get('/__testbed/coverage')
def coverage(): return cov()
@app.post('/__testbed/control/reset')
def reset(req:Request):
    if req.headers.get('x-testbed-control')!=CONTROL_TOKEN: return JSONResponse({'detail':'Not Found'},status_code=404)
    hits.clear()
    for k in auth: auth[k]=0
    return {'reset':True,'application':'fastapi-dynamic'}
@app.get('/',response_class=HTMLResponse)
def index(): return PAGE
@app.get('/login',response_class=HTMLResponse)
def login(): return PAGE
@app.post('/api/login')
async def api_login(req:Request):
    auth['loginAttempts']+=1
    b=await req.json()
    if b.get('username')!='zapuser' or b.get('password')!='ZapTest123!': auth['failedLogins']+=1; return JSONResponse({'ok':False},status_code=401)
    auth['successfulLogins']+=1; sid=secrets.token_urlsafe(24);sessions[sid]='zapuser';r=JSONResponse({'ok':True});r.set_cookie('sid',sid,httponly=True,samesite='lax');return r
@app.get('/private')
def private(req:Request):
    u=mark(req,'/private')
    if not u: return RedirectResponse('/login',302)
    return HTMLResponse('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=FASTAPI_DYNAMIC</p><ul><li><a href="/api/profile">profile</a></li><li><a href="/api/orders">orders</a></li><li><a href="/api/documents">documents</a></li></ul>')
@app.get('/api/profile')
def profile(req:Request):
    u=mark(req,'/api/profile'); return {'authenticated':True,'username':u,'profile':{'role':'tester'}} if u else JSONResponse({'authenticated':False},status_code=401)
@app.get('/api/orders')
def orders(req:Request):
    u=mark(req,'/api/orders'); return {'authenticated':True,'username':u,'orders':[{'id':101}]} if u else JSONResponse({'authenticated':False},status_code=401)
@app.get('/api/documents')
def documents(req:Request):
    u=mark(req,'/api/documents'); return {'authenticated':True,'username':u,'documents':[{'id':'DOC-1'}]} if u else JSONResponse({'authenticated':False},status_code=401)
@app.get('/api/whoami')
def whoami(req:Request):
    u=current(req); auth['authenticatedRequests' if u else 'unauthorizedRequests']+=1
    return {'authenticated':bool(u),**({'username':u} if u else {}),'technology':'FASTAPI_DYNAMIC'}
@app.get('/logout')
def logout(req:Request):
    sid=req.cookies.get('sid');sessions.pop(sid,None);r=RedirectResponse('/login',302);r.delete_cookie('sid');return r
