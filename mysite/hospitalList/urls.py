from django.urls import path
from . import views

app_name = 'openedhospital'
urlpatterns = [
	path('',views.ListView.as_view(),name='index'),
]