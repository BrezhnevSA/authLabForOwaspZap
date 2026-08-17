import base64, json, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import spnego

PORT=int(os.getenv('PORT','8080'))

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    server_version='ZapAuthNtlm/1.0'

    def _write(self,status,obj,headers=None):
        body=json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)

    def _challenge(self,token=None):
        value='NTLM' + ((' '+base64.b64encode(token).decode()) if token else '')
        self.send_response(401)
        self.send_header('WWW-Authenticate', value)
        self.send_header('Content-Length','0')
        self.end_headers()

    def _authenticate(self):
        if getattr(self,'ntlm_ctx',None) is not None and self.ntlm_ctx.complete:
            return getattr(self.ntlm_ctx,'client_principal',None) or 'ZAPLAB\\zapuser'
        auth=self.headers.get('Authorization','')
        if not auth.startswith('NTLM '):
            self._challenge(); return None
        try:
            token=base64.b64decode(auth.split(' ',1)[1])
            if getattr(self,'ntlm_ctx',None) is None:
                self.ntlm_ctx=spnego.server(protocol='ntlm')
            out=self.ntlm_ctx.step(token)
            if not self.ntlm_ctx.complete:
                self._challenge(out); return None
            return getattr(self.ntlm_ctx,'client_principal',None) or 'ZAPLAB\\zapuser'
        except Exception as e:
            print('NTLM error:',repr(e),flush=True)
            self.ntlm_ctx=None
            self._challenge(); return None

    def do_GET(self):
        if self.path=='/health': return self._write(200,{'ok':True,'scenario':'ntlm'})
        user=self._authenticate()
        if user is None: return
        if self.path in ('/','/private','/api/whoami'):
            return self._write(200,{'authenticated':True,'username':user,'scenario':'ntlm','authType':'NTLM'})
        self._write(404,{'error':'not found'})

    def log_message(self,fmt,*args): print('%s - %s' % (self.client_address[0],fmt%args),flush=True)

ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
