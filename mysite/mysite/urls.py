"""mysite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from polls import views

#from login import views
import polls

router = routers.DefaultRouter()
#router.register(r'Users',views.UsersViewSet)

router.register(r'users',views.UsersViewSet)
router.register(r'hospitals',views.HospitalViewSet)
router.register(r'hospital',views.HEViewSet)
router.register(r'token',views.TokenViewSet)

urlpatterns = [
               path('', include(router.urls)),
               path('api-auth/',include('rest_framework.urls',namespace='rest_framework')),
               path('hospitalList/',include('hospitalList.urls')),
               path('login/', include('login.urls')),
               path('admin/', admin.site.urls),
               #path('polls/', include('polls.urls'))
               ]
