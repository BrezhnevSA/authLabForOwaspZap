from django.urls import path
from . import views
urlpatterns=[path('login',views.login_view),path('private',views.private),path('api/whoami',views.whoami),path('__testbed/expected',views.expected),path('__testbed/coverage',views.coverage),path('__testbed/control/reset',views.reset),path('logout',views.logout_view)]
