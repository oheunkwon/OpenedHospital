from django.views import View
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from .models import Hospitals
import json


from django.core.serializers import serialize
# Create your views here.
class ListView(View):

    def get(self,request):
        query=Hospitals.objects.all()
        data=json.loads(serialize('json',query))
        return JsonResponse({'items':data})
  
    def put(self, request):
        request=json.loads(request.body)
        id=request['id']
        name=request['name']
        query=get_object_or_404(Hospitals,pk=id)
        query.name=name
        query.save()
        return HttpResponse(status=200)


