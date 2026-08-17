import base64, json, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import gssapi

PORT=int(os.getenv('PORT','8080'))
class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def _json(self,status,obj,headers=None):
        b=json.dumps(obj).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)))
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers();self.wfile.write(b)
    def _challenge(self,token=None):
        h='Negotiate'+((' '+base64.b64encode(token).decode()) if token else '')
        self.send_response(401);self.send_header('WWW-Authenticate',h);self.send_header('Content-Length','0');self.end_headers()
    def _auth(self):
        if getattr(self,'gss_ctx',None) is not None and self.gss_ctx.complete:
            return str(self.gss_ctx.initiator_name)
        h=self.headers.get('Authorization','')
        if not h.startswith('Negotiate '): self._challenge();return None
        try:
            token=base64.b64decode(h.split(' ',1)[1])
            if getattr(self,'gss_ctx',None) is None: self.gss_ctx=gssapi.SecurityContext(usage='accept')
            out=self.gss_ctx.step(token)
            if not self.gss_ctx.complete:
                self._challenge(bytes(out) if out else None);return None
            # A final Negotiate token can be returned with 200.
            self.final_token=bytes(out) if out else None
            return str(self.gss_ctx.initiator_name)
        except Exception as e:
            print('Kerberos error',repr(e),flush=True);self.gss_ctx=None;self._challenge();return None
    def do_GET(self):
        if self.path=='/health': return self._json(200,{'ok':True,'scenario':'kerberos-spnego'})
        user=self._auth()
        if user is None:return
        hdr={}
        if getattr(self,'final_token',None):hdr['WWW-Authenticate']='Negotiate '+base64.b64encode(self.final_token).decode();self.final_token=None
        if self.path in ('/','/private','/api/whoami'):return self._json(200,{'authenticated':True,'username':user,'scenario':'kerberos-spnego','authType':'Kerberos/SPNEGO'},hdr)
        self._json(404,{'error':'not found'},hdr)
ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
