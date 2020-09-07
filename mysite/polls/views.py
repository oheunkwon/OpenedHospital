from django.http import HttpResponse,JsonResponse
from rest_framework import viewsets, permissions, status
from .serializers import UsersSerializer,HospitalsSerializer,HESerializer,TokenSerializer
from .models import Users,Hospitals,Hospitaledithistories,Token
from mysite.settings import SECRET_KEY
from rest_framework.decorators import action
from rest_framework.response import Response
import json
import bcrypt
import jwt
import re
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
        p=re.compile('^[\w\-]+@(?:(?:[\w\-]{2,}\.)+[a-zA-Z]{2,})$')
        q=re.compile('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!#%*?&])[A-Za-z\d$@$!%*?#&_\-~]{6,100}')
        validemail = p.match(email)
        validpwd= q.match(pwd)
        if validemail and validpwd:
            try:
                if email and pwd:
                    db = Users.objects.get(email=email)#db에 저장되어있는 값 -db에서5agrvd@gmail.com
                    # db.pwd == pwd:
                    if bcrypt.checkpw(pwd.encode('UTF-8'), db.pwd.encode('UTF-8')):
                        #token = jwt.encode({'user' : db.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
                        return Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
                    else:
                        return Response("Status 4010 : 로그인 정보가 일치하지 않습니다.", status=status.HTTP_401_UNAUTHORIZED)
            except Exception as e:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
        else :
            return Response("Status 4004 : 잘못된 형식 - 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)


    @action(methods=['POST'], detail=False)
    def signup(self, request): #회원가입
        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111
        name = request.POST.get('name',False)
        address = request.POST.get('address',False)
        p = re.compile('^[\w\-]+@(?:(?:[\w\-]{2,}\.)+[a-zA-Z]{2,})$') #email validation
        q = re.compile('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!#%*?&])[A-Za-z\d$@$!%*?#&_\-~]{6,100}') #pwd validation
        r = re.compile('^([ㄱ-ㅎㅏ-ㅣ가-힣]\s{0,}){1,100}|([a-zA-Z]\s{0,}){1,100}$') #name validation
        s = re.compile('^([가-힣0-9]\s{0,}){6,200}|([a-zA-Z0-9]\s{0,}){6,200}$')
        validemail = p.match(email)
        validpwd = q.match(pwd)
        validname = r.match(name)
        validaddress = s.match(address)
        if validemail and validpwd and validname and validaddress:
            if name and email and address and pwd:
                Users.objects.create(email=email,
                                    pwd =bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"),
                                    name =name,
                                    address =address)
                return Response("201 created", status=status.HTTP_201_CREATED)
            else:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response("Status 4004 : 잘못된 형식- 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)


    @action(methods=['PUT'], detail=False) # 비밀번호 찾기/재설정
    def password(self, request): #회원가입

        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111

        if email and pwd:

            Users.objects.create(email=email,
                                 pwd=bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"),)

            return Response("201 created", status=status.HTTP_201_CREATED)
        else:
            return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)


class HospitalViewSet(viewsets.ModelViewSet):
    queryset = Hospitals.objects.all() #hospitals에 있는 모든 데이터 다 가져옴.
    #hospitaldata=Hospitals.objects.values()

    serializer_class = HospitalsSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(methods=['POST'], detail=False)
    def registerhospital(self, request):
        name = request.POST.get('name',False) # postman에서 입력한 값
        tel = request.POST.get('tel',False)
        address = request.POST.get('address',False)
        opstatus = request.POST.get('status',False)
        p = re.compile('^([ㄱ-ㅎㅏ-ㅣ가-힣]\s{0,}){1,100}|([a-zA-Z]\s{0,}){1,100}$')  # name validation
        q = re.compile('^(^0[0-9]{1,2})(-)?([0-9]{3,4})(-)?([0-9]{4})$') # tel validation
        r = re.compile('^([가-힣0-9]\s{0,}){6,200}|([a-zA-Z0-9]\s{0,}){6,200}$') #address validation
        s = re.compile('^(OPEN|CLOSED)$') #status validation
        validname = p.match(name)
        validtel = q.match(tel)
        validaddress = r.match(address)
        validstatus = s.match(opstatus)
        #id = request.GET.get('id',False)
        if validname and validtel and validaddress and validstatus:
            if name and tel and address and opstatus:
                data = Hospitals.objects.create(name=name, tel=tel, address=address, status=opstatus)
                return Response("201 created", status=status.HTTP_201_CREATED)
                #return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
                #JsonResponse({'dddd': address})
        else:
            return Response("Status 4004 : 잘못된 형식 - 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False)
    def hospitalId(self, request): #병원정보 변경,병원상세보기
        name = request.POST.get('name', False)  # postman에서 입력한 값
        #tel = request.POST.get('tel', False)
        #address = request.POST.get('address', False)
        #opstatus = request.POST.get('status', False)
        # id = request.GET.get('id',False)
        if name :#and tel and address and opstatus:
            #data = Hospitals.objects.create(name=name, tel=tel, address=address, status=opstatus)
            data = Hospitals.objects.get(name=name)
            #name=data.name.decode("UTF-8")
            #name=name.encode().decode()
            tel=data.tel
            address=data.address
            opstatus=data.status
            serializer_class = HospitalsSerializer
            permission_classes = [permissions.IsAuthenticated]
            return JsonResponse({'name': name,'tel':tel, 'address':address,'status':opstatus },status=202)
                #Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
            # return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
        else:
            #return JsonResponse({'dddd': data})
             Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)


class HEViewSet(viewsets.ModelViewSet):
    queryset = Hospitaledithistories.objects.all()
    serializer_class = HESerializer
    permission_classes = [permissions.IsAuthenticated]



class TokenViewSet(viewsets.ModelViewSet):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    permission_classes = [permissions.IsAuthenticated]



# Create your views here.
