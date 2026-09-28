from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

CONTROL_TOKEN='zap-testbed-reset-v1'
EXPECTED=['/private']
hits={}
auth={'loginAttempts':0,'successfulLogins':0,'failedLogins':0,'authenticatedRequests':0,'unauthorizedRequests':0}
def track(p):
    if p in EXPECTED: hits[p]=hits.get(p,0)+1
def coverage_data():
    visited=[p for p in EXPECTED if p in hits]
    return {'application':'django-form','scenario':'form-cookie','discovery':{'expected':len(EXPECTED),'visited':len(visited),'coveragePercent':round(len(visited)*100/len(EXPECTED),2),'visitedEndpoints':visited,'missingEndpoints':[p for p in EXPECTED if p not in hits]},'authentication':dict(auth)}
def login_view(request):
    if request.method == 'POST':
        auth['loginAttempts']+=1
        if request.POST.get('username') == 'zapuser' and request.POST.get('password') == 'ZapTest123!':
            auth['successfulLogins']+=1; request.session['user'] = 'zapuser'; return redirect('/private')
        auth['failedLogins']+=1; return render(request, 'login.html', {'error': 'bad credentials'}, status=401)
    return render(request, 'login.html')
def private(request):
    track('/private')
    if request.session.get('user') != 'zapuser': auth['unauthorizedRequests']+=1; return redirect('/login')
    auth['authenticatedRequests']+=1
    return HttpResponse('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=DJANGO</p><a href="/api/whoami">whoami</a>')
def whoami(request):
    user = request.session.get('user'); auth['authenticatedRequests' if user else 'unauthorizedRequests']+=1
    if user: return JsonResponse({'authenticated': True, 'username': user, 'technology': 'DJANGO'})
    return JsonResponse({'authenticated': False, 'technology': 'DJANGO'})
def expected(request): return JsonResponse({'application':'django-form','expectedEndpoints':EXPECTED})
def coverage(request): return JsonResponse(coverage_data())
@csrf_exempt
def reset(request):
    if request.method!='POST' or request.headers.get('X-Testbed-Control')!=CONTROL_TOKEN: return JsonResponse({'error':'not found'},status=404)
    hits.clear()
    for k in auth: auth[k]=0
    return JsonResponse({'reset':True,'application':'django-form'})
def logout_view(request): request.session.flush(); return redirect('/login')
