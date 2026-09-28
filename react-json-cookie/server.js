import express from 'express';
import session from 'express-session';
import path from 'path';
import {fileURLToPath} from 'url';
const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const CONTROL_TOKEN=process.env.TESTBED_CONTROL_TOKEN||'zap-testbed-reset-v1';
const EXPECTED=['/private','/api/profile','/api/orders','/api/documents'];
const hits=new Map();
const auth={loginAttempts:0,successfulLogins:0,failedLogins:0,authenticatedRequests:0,unauthorizedRequests:0};
function track(p){if(EXPECTED.includes(p))hits.set(p,(hits.get(p)||0)+1)}
function coverage(){const v=EXPECTED.filter(p=>hits.has(p));return {application:'react-json-cookie',scenario:'json-login-cookie-session',discovery:{expected:EXPECTED.length,visited:v.length,coveragePercent:Number((v.length*100/EXPECTED.length).toFixed(2)),visitedEndpoints:v,missingEndpoints:EXPECTED.filter(p=>!hits.has(p))},authentication:{...auth}}}
function reset(){hits.clear();Object.keys(auth).forEach(k=>auth[k]=0)}
function protectedJson(req,res,p,body){track(p);if(!req.session.user){auth.unauthorizedRequests++;return res.status(401).json({authenticated:false,error:'login required'})}auth.authenticatedRequests++;res.json({authenticated:true,username:req.session.user,...body})}
app.use(express.json());
app.use(session({secret:'zap-testbed-only',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax'}}));
app.get('/__testbed/expected',(_q,r)=>r.json({application:'react-json-cookie',expectedEndpoints:EXPECTED}));
app.get('/__testbed/coverage',(_q,r)=>r.json(coverage()));
app.post('/__testbed/control/reset',(q,r)=>{if(q.get('X-Testbed-Control')!==CONTROL_TOKEN)return r.sendStatus(404);reset();r.json({reset:true,application:'react-json-cookie'})});
app.post('/api/login',(req,res)=>{auth.loginAttempts++;if(req.body.username==='zapuser'&&req.body.password==='ZapTest123!'){auth.successfulLogins++;req.session.user='zapuser';return res.json({ok:true})}auth.failedLogins++;res.status(401).json({ok:false})});
app.get('/private',(req,res)=>{track('/private');if(!req.session.user){auth.unauthorizedRequests++;return res.redirect('/login')}auth.authenticatedRequests++;res.send('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=REACT_JSON_COOKIE</p><ul><li><a href="/api/profile">profile</a></li><li><a href="/api/orders">orders</a></li><li><a href="/api/documents">documents</a></li></ul><a href="/api/whoami">whoami</a>')});
app.get('/api/profile',(q,r)=>protectedJson(q,r,'/api/profile',{profile:{role:'tester'}}));
app.get('/api/orders',(q,r)=>protectedJson(q,r,'/api/orders',{orders:[{id:101}]}));
app.get('/api/documents',(q,r)=>protectedJson(q,r,'/api/documents',{documents:[{id:'DOC-1'}]}));
app.get('/api/whoami',(req,res)=>{if(req.session.user)auth.authenticatedRequests++;else auth.unauthorizedRequests++;res.json(req.session.user?{authenticated:true,username:req.session.user,technology:'REACT_JSON_COOKIE'}:{authenticated:false,technology:'REACT_JSON_COOKIE'})});
app.get('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login')));
app.use(express.static(path.join(__dirname,'dist')));
app.get(['/','/login'],(req,res)=>res.sendFile(path.join(__dirname,'dist','index.html')));
app.listen(3000,'0.0.0.0');
