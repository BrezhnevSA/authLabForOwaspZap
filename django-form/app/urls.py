from django.urls import path
from . import views
urlpatterns=[path('login',views.login_view),path('private',views.private),path('api/whoami',views.whoami),path('logout',views.logout_view)]
