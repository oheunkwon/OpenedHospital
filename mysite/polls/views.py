from django.http import HttpResponse
from rest_framework import viewsets,permissions
from .serializers import UsersSerializer,HospitalsSerializer,HESerializer,TokenSerializer
from .models import Users,Hospitals,Hospitaledithistories,Token


class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()#user에 있는 모든 데이터 다 가져옴.
    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated] #인증된 사용자에게만 액세스 허용

class HospitalViewSet(viewsets.ModelViewSet):
    queryset = Hospitals.objects.all() #hospitals에 있는 모든 데이터 다 가져옴.
    serializer_class = HospitalsSerializer
    permission_classes = [permissions.IsAuthenticated]

class HEViewSet(viewsets.ModelViewSet):
    queryset = Hospitaledithistories.objects.all()
    serializer_class = HESerializer
    permission_classes = [permissions.IsAuthenticated]

class TokenViewSet(viewsets.ModelViewSet):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    permission_classes = [permissions.IsAuthenticated]



# Create your views here.
