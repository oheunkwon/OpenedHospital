from django.urls import path

from . import views


urlpatterns = [
               #path('', views.index, name='index'),#127.0.0.1:8000요청 올 경우 views.index()실행.
               #path('',views.SignUpView.as_view(),name='signup')
                #path('',SignupView.as_view())
               ]
