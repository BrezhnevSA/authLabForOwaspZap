import express from 'express';
import session from 'express-session';

const app = express();
const CONTROL_TOKEN = process.env.TESTBED_CONTROL_TOKEN || 'zap-testbed-reset-v1';
const EXPECTED = ['/private'];
const hits = new Map();
const auth = { loginAttempts:0, successfulLogins:0, failedLogins:0, authenticatedRequests:0, unauthorizedRequests:0 };

function track(path){ if(EXPECTED.includes(path)) hits.set(path,(hits.get(path)||0)+1); }
function coverage(){
  const visited=EXPECTED.filter(p=>hits.has(p));
  return {application:'express-form',scenario:'form-cookie',discovery:{expected:EXPECTED.length,visited:visited.length,coveragePercent:EXPECTED.length?Number((visited.length*100/EXPECTED.length).toFixed(2)):100,visitedEndpoints:visited,missingEndpoints:EXPECTED.filter(p=>!hits.has(p))},authentication:{...auth}};
}
function reset(){hits.clear();for(const k of Object.keys(auth))auth[k]=0;}

app.set('view engine','ejs'); app.set('views','./views');
app.use(express.urlencoded({extended:false}));
app.use(session({secret:'zap-testbed-only',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax'}}));
app.get('/__testbed/expected',(_req,res)=>res.json({application:'express-form',expectedEndpoints:EXPECTED}));
app.get('/__testbed/coverage',(_req,res)=>res.json(coverage()));
app.post('/__testbed/control/reset',(req,res)=>{if(req.get('X-Testbed-Control')!==CONTROL_TOKEN)return res.sendStatus(404);reset();res.json({reset:true,application:'express-form'});});
app.get('/login',(req,res)=>res.render('login',{error:null}));
app.post('/login',(req,res)=>{auth.loginAttempts++;if(req.body.username==='zapuser'&&req.body.password==='ZapTest123!'){auth.successfulLogins++;req.session.user='zapuser';return res.redirect('/private')}auth.failedLogins++;res.status(401).render('login',{error:'bad credentials'})});
app.get('/private',(req,res)=>{track('/private');if(!req.session.user){auth.unauthorizedRequests++;return res.redirect('/login')}auth.authenticatedRequests++;res.send('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=EXPRESS</p><a href="/api/whoami">whoami</a>')});
app.get('/api/whoami',(req,res)=>{if(req.session.user)auth.authenticatedRequests++;else auth.unauthorizedRequests++;res.json(req.session.user?{authenticated:true,username:req.session.user,technology:'EXPRESS'}:{authenticated:false,technology:'EXPRESS'})});
app.get('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login')));
app.listen(3000,'0.0.0.0');
