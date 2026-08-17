from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect


def login_view(request):
    if request.method == 'POST':
        if request.POST.get('username') == 'zapuser' and request.POST.get('password') == 'ZapTest123!':
            request.session['user'] = 'zapuser'
            return redirect('/private')
        return render(request, 'login.html', {'error': 'bad credentials'}, status=401)
    return render(request, 'login.html')


def private(request):
    if request.session.get('user') != 'zapuser':
        return redirect('/login')
    return HttpResponse('<h1>AUTHENTICATED</h1><p>user=zapuser</p><p>technology=DJANGO</p><a href="/api/whoami">whoami</a>')


def whoami(request):
    user = request.session.get('user')
    if user:
        return JsonResponse({'authenticated': True, 'username': user, 'technology': 'DJANGO'})
    return JsonResponse({'authenticated': False, 'technology': 'DJANGO'})


def logout_view(request):
    request.session.flush()
    return redirect('/login')
