import base64,json,os,threading
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import gssapi
PORT=int(os.getenv('PORT','8080'));CONTROL_TOKEN=os.getenv('TESTBED_CONTROL_TOKEN','zap-testbed-reset-v1');EXPECTED=['/private'];lock=threading.Lock();hits={};stats={'challenges':0,'authenticatedRequests':0,'unauthorizedRequests':0}
def track(p):
 if p in EXPECTED:
  with lock:hits[p]=hits.get(p,0)+1
def coverage():
 with lock:
  v=[p for p in EXPECTED if p in hits];return {'application':'kerberos-web','scenario':'kerberos-spnego','discovery':{'expected':len(EXPECTED),'visited':len(v),'coveragePercent':round(len(v)*100/len(EXPECTED),2),'visitedEndpoints':v,'missingEndpoints':[p for p in EXPECTED if p not in hits]},'authentication':dict(stats)}
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def _json(self,s,o,h=None):
  b=json.dumps(o).encode();self.send_response(s);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));[self.send_header(k,v) for k,v in (h or {}).items()];self.end_headers();self.wfile.write(b)
 def _challenge(self,t=None):
  with lock:stats['challenges']+=1;stats['unauthorizedRequests']+=1
  h='Negotiate'+((' '+base64.b64encode(t).decode()) if t else '');self.send_response(401);self.send_header('WWW-Authenticate',h);self.send_header('Content-Length','0');self.end_headers()
 def _auth(self):
  if getattr(self,'gss_ctx',None) is not None and self.gss_ctx.complete:return str(self.gss_ctx.initiator_name)
  h=self.headers.get('Authorization','')
  if not h.startswith('Negotiate '):self._challenge();return None
  try:
   token=base64.b64decode(h.split(' ',1)[1]);
   if getattr(self,'gss_ctx',None) is None:self.gss_ctx=gssapi.SecurityContext(usage='accept')
   out=self.gss_ctx.step(token)
   if not self.gss_ctx.complete:self._challenge(bytes(out) if out else None);return None
   self.final_token=bytes(out) if out else None;return str(self.gss_ctx.initiator_name)
  except Exception as e:print('Kerberos error',repr(e),flush=True);self.gss_ctx=None;self._challenge();return None
 def do_POST(self):
  if self.path=='/__testbed/control/reset':
   if self.headers.get('X-Testbed-Control')!=CONTROL_TOKEN:return self._json(404,{'error':'not found'})
   with lock:hits.clear();stats.update({k:0 for k in stats})
   return self._json(200,{'reset':True,'application':'kerberos-web'})
  self._json(404,{'error':'not found'})
 def do_GET(self):
  if self.path=='/health':return self._json(200,{'ok':True,'scenario':'kerberos-spnego'})
  if self.path=='/__testbed/expected':return self._json(200,{'application':'kerberos-web','expectedEndpoints':EXPECTED})
  if self.path=='/__testbed/coverage':return self._json(200,coverage())
  user=self._auth();
  if user is None:return
  with lock:stats['authenticatedRequests']+=1
  hdr={}
  if getattr(self,'final_token',None):hdr['WWW-Authenticate']='Negotiate '+base64.b64encode(self.final_token).decode();self.final_token=None
  if self.path in ('/','/private','/api/whoami'):
   if self.path=='/private':track('/private')
   return self._json(200,{'authenticated':True,'username':user,'scenario':'kerberos-spnego','authType':'Kerberos/SPNEGO'},hdr)
  self._json(404,{'error':'not found'},hdr)
ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
