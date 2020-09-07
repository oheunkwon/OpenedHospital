from django.shortcuts import render

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets,permissions
from rest_framework.parsers import JSONParser
from .serializers import UsersSerializer
from .models import Users
from rest_framework.decorators import action
from rest_framework.response import Response

class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()#user에 있는 모든 데이터 다 가져옴.
    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated]
# Create your views here.

    #@csrf_exempt
    @action(methods=['post'], detail=False)
    def login(request):
        email=request.POST.get('email',False)
        pwd=request.POST.get('pwd',False)
        if email and pwd:
            try:
                email=Users.objects.get(email=email)
                pwd=Users.objects.get(pwd=pwd)
                return Response("202 Accepted",status=status.HTTP_202_accepted)
            except Exception as e:
                return Response("Status 4010 : 로그인 정보가 일치하지 않습니다.",status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response("Status 4004 : 다시 입력해 주세요. ",status=status.HTTP_400_BAD_REQUEST)
