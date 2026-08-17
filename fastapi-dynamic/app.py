from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import secrets
app=FastAPI(); sessions={}
PAGE="""<!doctype html><html><body><h1>FastAPI Dynamic Login</h1><p>The login controls are created only after JavaScript interaction.</p><button id="open">Sign in</button><div id="slot"></div><script>
document.getElementById('open').onclick=()=>{document.getElementById('slot').innerHTML=`<div id="modal"><label>Username <input id="u" name="username" autocomplete="username"></label><br><label>Password <input id="p" name="password" type="password" autocomplete="current-password"></label><br><button id="go">Login</button><p id="msg"></p></div>`;document.getElementById('go').onclick=async()=>{let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});if(r.ok)location='/private';else document.getElementById('msg').textContent='bad credentials';};};
</script></body></html>"""
def current(req): return sessions.get(req.cookies.get('sid',''))
@app.get('/',response_class=HTMLResponse)
def index(): return PAGE
@app.get('/login',response_class=HTMLResponse)
def login(): return PAGE
@app.post('/api/login')
async def api_login(req:Request):
    b=await req.json()
    if b.get('username')!='zapuser' or b.get('password')!='ZapTest123!': return JSONResponse({'ok':False},status_code=401)
    sid=secrets.token_urlsafe(24);sessions[sid]='zapuser';r=JSONResponse({'ok':True});r.set_cookie('sid',sid,httponly=True,samesite='lax');return r
@app.get('/private')
def private(req:Request):
    if not current(req): return RedirectResponse('/login',302)
    return HTMLResponse('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=FASTAPI_DYNAMIC</p><a href="/api/whoami">whoami</a>')
@app.get('/api/whoami')
def whoami(req:Request):
    u=current(req);return {'authenticated':bool(u),**({'username':u} if u else {}),'technology':'FASTAPI_DYNAMIC'}
@app.get('/logout')
def logout(req:Request):
    sid=req.cookies.get('sid');sessions.pop(sid,None);r=RedirectResponse('/login',302);r.delete_cookie('sid');return r
