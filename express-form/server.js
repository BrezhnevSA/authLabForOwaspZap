import express from 'express'; import session from 'express-session';
const app=express(); app.set('view engine','ejs'); app.set('views','./views'); app.use(express.urlencoded({extended:false})); app.use(session({secret:'zap-testbed-only',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax'}}));
app.get('/login',(req,res)=>res.render('login',{error:null}));
app.post('/login',(req,res)=>{if(req.body.username==='zapuser'&&req.body.password==='ZapTest123!'){req.session.user='zapuser';return res.redirect('/private')}res.status(401).render('login',{error:'bad credentials'})});
app.get('/private',(req,res)=>{if(!req.session.user)return res.redirect('/login');res.send('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=EXPRESS</p><a href="/api/whoami">whoami</a>')});
app.get('/api/whoami',(req,res)=>res.json(req.session.user?{authenticated:true,username:req.session.user,technology:'EXPRESS'}:{authenticated:false,technology:'EXPRESS'}));
app.get('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login'))); app.listen(3000,'0.0.0.0');
