from django.http import HttpResponse,JsonResponse
from rest_framework import viewsets, permissions, status
from .serializers import UsersSerializer,HospitalsSerializer,HESerializer,TokenSerializer
from .models import Users,Hospitals,Hospitaledithistories,Token
from rest_framework.decorators import action
from rest_framework.response import Response
import json
class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()#user에 있는 모든 데이터 다 가져옴.
    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated] #인증된 사용자에게만 액세스 허용
    #~~~users/login/
    @action(methods = ['POST'], detail=False)
    def login(self, request):
        email = request.POST.get('email', False)#postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)#11111
        #if email and pwd:
        #pwd = Users.objects.get(pwd=pwd)
        try:
            if email and pwd:
                db = Users.objects.get(email=email)#db에 저장되어있는 값 -db에서5agrvd@gmail.com
                #pwd_input = Users.objects.get(pwd=pwd)# 11111 db에 저장된 11111인 값을 불러옴
                #return Response("ddd",email_input)
                #
                if db.pwd == pwd:
                    return Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
                else:
                    return Response("Status 4010 : 로그인 정보가 일치하지 않습니다.", status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False)
    def registusers(self, request):
        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111
        name = request.POST.get('name',False)

        address = request.POST.get('address',False)

        #id = request.GET.get('id',False)
        if name and email and address and pwd:
            try:
                data=Users.objects.create(email=email, pwd=pwd, name=name, address=address)
                data.save()

                return Response("201 created", status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

class HospitalViewSet(viewsets.ModelViewSet):
    queryset = Hospitals.objects.all() #hospitals에 있는 모든 데이터 다 가져옴.
    serializer_class = HospitalsSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(methods=['POST'], detail=False)
    def registerhospital(self, request):

        name = request.POST.get('name',False) # postman에서 입력한 값
        tel = request.POST.get('tel',False)
        address = request.POST.get('address',False)
        status = request.POST.get('status',False)
        #id = request.GET.get('id',False)
        if name and tel and address and status:
            try:

                data = Hospitals.objects.create(name=name, tel=tel, address=address, status=status)
                data.save()

                return Response("201 created", status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)



class HEViewSet(viewsets.ModelViewSet):
    queryset = Hospitaledithistories.objects.all()
    serializer_class = HESerializer
    permission_classes = [permissions.IsAuthenticated]

class TokenViewSet(viewsets.ModelViewSet):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    permission_classes = [permissions.IsAuthenticated]



# Create your views here.
