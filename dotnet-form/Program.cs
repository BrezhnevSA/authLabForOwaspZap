using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Collections.Concurrent;
using System.Security.Claims;

var builder=WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o=>o.LoginPath="/login");
builder.Services.AddAuthorization(); builder.Services.AddAntiforgery();
var app=builder.Build(); app.UseAuthentication(); app.UseAuthorization();

const string controlToken="zap-testbed-reset-v1";
var expected=new[]{"/private"};
var hits=new ConcurrentDictionary<string,int>();
int loginAttempts=0,successfulLogins=0,failedLogins=0,authenticatedRequests=0,unauthorizedRequests=0;
object Coverage(){var visited=expected.Where(hits.ContainsKey).ToArray();return new {application="dotnet-form",scenario="form-cookie-antiforgery",discovery=new {expected=expected.Length,visited=visited.Length,coveragePercent=expected.Length==0?100.0:visited.Length*100.0/expected.Length,visitedEndpoints=visited,missingEndpoints=expected.Where(x=>!hits.ContainsKey(x)).ToArray()},authentication=new {loginAttempts,successfulLogins,failedLogins,authenticatedRequests,unauthorizedRequests}};}
void Track(string p){if(expected.Contains(p))hits.AddOrUpdate(p,1,(_,v)=>v+1);}

app.MapGet("/__testbed/expected",()=>Results.Json(new {application="dotnet-form",expectedEndpoints=expected}));
app.MapGet("/__testbed/coverage",()=>Results.Json(Coverage()));
app.MapPost("/__testbed/control/reset",(HttpContext c)=>{if(c.Request.Headers["X-Testbed-Control"]!=controlToken)return Results.NotFound(new {error="not found"});hits.Clear();loginAttempts=successfulLogins=failedLogins=authenticatedRequests=unauthorizedRequests=0;return Results.Json(new {reset=true,application="dotnet-form"});});
app.MapGet("/login",(HttpContext c,Microsoft.AspNetCore.Antiforgery.IAntiforgery af)=>{var t=af.GetAndStoreTokens(c);return Results.Content($"""<!doctype html><html><body><h1>ASP.NET Form Login</h1><form method='post' action='/login'><input type='hidden' name='{t.FormFieldName}' value='{t.RequestToken}'><label>Username <input name='username' autocomplete='username'></label><br><label>Password <input type='password' name='password' autocomplete='current-password'></label><br><button>Sign in</button></form></body></html>""","text/html");});
app.MapPost("/login",async (HttpContext c,Microsoft.AspNetCore.Antiforgery.IAntiforgery af)=>{loginAttempts++;await af.ValidateRequestAsync(c);var f=await c.Request.ReadFormAsync();if(f["username"]=="zapuser"&&f["password"]=="ZapTest123!"){successfulLogins++;var id=new ClaimsIdentity(new[]{new Claim(ClaimTypes.Name,"zapuser")},CookieAuthenticationDefaults.AuthenticationScheme);await c.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,new ClaimsPrincipal(id));return Results.Redirect("/private");}failedLogins++;return Results.Unauthorized();});
app.MapGet("/private",(HttpContext c)=>{Track("/private");if(c.User.Identity?.IsAuthenticated==true){authenticatedRequests++;return Results.Content("<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=ASPNET_CORE</p><a href='/api/whoami'>whoami</a>","text/html");}unauthorizedRequests++;return Results.Redirect("/login");});
app.MapGet("/api/whoami",(HttpContext c)=>{if(c.User.Identity?.IsAuthenticated==true){authenticatedRequests++;return Results.Json(new {authenticated=true,username=c.User.Identity.Name,technology="ASPNET_CORE"});}unauthorizedRequests++;return Results.Json(new {authenticated=false,technology="ASPNET_CORE"});});
app.MapGet("/logout",async (HttpContext c)=>{await c.SignOutAsync();return Results.Redirect("/login");});
app.Run();
