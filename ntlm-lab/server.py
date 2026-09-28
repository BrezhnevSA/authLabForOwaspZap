import base64,json,os,threading
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import spnego
PORT=int(os.getenv('PORT','8080'));CONTROL_TOKEN=os.getenv('TESTBED_CONTROL_TOKEN','zap-testbed-reset-v1');EXPECTED=['/private'];lock=threading.Lock();hits={};stats={'challenges':0,'authenticatedRequests':0,'unauthorizedRequests':0}
def track(p):
  if p in EXPECTED:
    with lock:hits[p]=hits.get(p,0)+1
def coverage():
  with lock:
    v=[p for p in EXPECTED if p in hits];return {'application':'ntlm-auth','scenario':'ntlm','discovery':{'expected':len(EXPECTED),'visited':len(v),'coveragePercent':round(len(v)*100/len(EXPECTED),2),'visitedEndpoints':v,'missingEndpoints':[p for p in EXPECTED if p not in hits]},'authentication':dict(stats)}
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1';server_version='ZapAuthNtlm/1.0'
 def _write(self,s,o,h=None):
  b=json.dumps(o).encode();self.send_response(s);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));[self.send_header(k,v) for k,v in (h or {}).items()];self.end_headers();self.wfile.write(b)
 def _challenge(self,t=None):
  with lock:stats['challenges']+=1;stats['unauthorizedRequests']+=1
  v='NTLM'+((' '+base64.b64encode(t).decode()) if t else '');self.send_response(401);self.send_header('WWW-Authenticate',v);self.send_header('Content-Length','0');self.end_headers()
 def _authenticate(self):
  if getattr(self,'ntlm_ctx',None) is not None and self.ntlm_ctx.complete:return getattr(self.ntlm_ctx,'client_principal',None) or 'ZAPLAB\\zapuser'
  a=self.headers.get('Authorization','');
  if not a.startswith('NTLM '):self._challenge();return None
  try:
   token=base64.b64decode(a.split(' ',1)[1]);
   if getattr(self,'ntlm_ctx',None) is None:self.ntlm_ctx=spnego.server(protocol='ntlm')
   out=self.ntlm_ctx.step(token)
   if not self.ntlm_ctx.complete:self._challenge(out);return None
   return getattr(self.ntlm_ctx,'client_principal',None) or 'ZAPLAB\\zapuser'
  except Exception as e:print('NTLM error:',repr(e),flush=True);self.ntlm_ctx=None;self._challenge();return None
 def do_POST(self):
  if self.path=='/__testbed/control/reset':
   if self.headers.get('X-Testbed-Control')!=CONTROL_TOKEN:return self._write(404,{'error':'not found'})
   with lock:hits.clear();stats.update({k:0 for k in stats})
   return self._write(200,{'reset':True,'application':'ntlm-auth'})
  self._write(404,{'error':'not found'})
 def do_GET(self):
  if self.path=='/health':return self._write(200,{'ok':True,'scenario':'ntlm'})
  if self.path=='/__testbed/expected':return self._write(200,{'application':'ntlm-auth','expectedEndpoints':EXPECTED})
  if self.path=='/__testbed/coverage':return self._write(200,coverage())
  user=self._authenticate();
  if user is None:return
  with lock:stats['authenticatedRequests']+=1
  if self.path in ('/','/private','/api/whoami'):
   if self.path=='/private':track('/private')
   return self._write(200,{'authenticated':True,'username':user,'scenario':'ntlm','authType':'NTLM'})
  self._write(404,{'error':'not found'})
 def log_message(self,fmt,*args):print('%s - %s'%(self.client_address[0],fmt%args),flush=True)
ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
