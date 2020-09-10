from urllib.parse import urlparse

from django.http import HttpResponse,JsonResponse
from django.views import View
from rest_framework import viewsets, permissions, status
from .serializers import UsersSerializer,HospitalsSerializer,HESerializer,TokenSerializer
from .models import Users,Hospitals,Hospitaledithistories,Token
from mysite.settings import SECRET_KEY
from rest_framework.decorators import action
from rest_framework.response import Response
from django.core.mail import send_mail
import json
import sys
import pandas as pd
import requests
from urllib.parse import urlparse

from datetime import *
import pymysql
from openpyxl import Workbook
from openpyxl import load_workbook
import bcrypt
import jwt
import re


APP_KEY=''
URL = 'https://dapi.kakao.com/v2/local/search/address.json?query='

#하드코딩 고칠 것-에러코드

class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()#user에 있는 모든 데이터 다 가져옴.
    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated]#인증된 사용자에게만 액세스 허용
    #012.로그인 ~~~users/login/
    @action(methods = ['POST'], detail=False)
    def login(self, request):
        email = request.POST.get('email', False)#postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)#11111
        if email and pwd:
            db = Users.objects.get(email=email)#db에 저장되어있는 값 -db에서5agrvd@gmail.com
            if bcrypt.checkpw(pwd.encode('UTF-8'), db.pwd.encode('UTF-8')):
                return Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
            else:
                return Response("Status 4010 : 로그인 정보가 일치하지 않습니다.", status=status.HTTP_401_UNAUTHORIZED)
        return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

    #v1/users/
    @action(methods=['POST'], detail=False)
    def signup(self, request): #회원가입
        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111
        name = request.POST.get('name',False)
        address = request.POST.get('address',False)
        a = re.compile('^[\w\-]+@(?:(?:[\w\-]{2,}\.)+[a-zA-Z]{2,})$') #email validation
        b = re.compile('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!#%*?&])[A-Za-z\d$@$!%*?#&_\-~]{6,100}') #pwd validation
        c = re.compile('^([ㄱ-ㅎㅏ-ㅣ가-힣]\s{0,}){1,100}|([a-zA-Z]\s{0,}){1,100}$') #name validation
        d = re.compile('^([가-힣0-9]\s{0,}){6,200}|([a-zA-Z0-9]\s{0,}){6,200}$') #address validation
        #return JsonResponse({'dddd': address, 'pwd': token})
        validemail = a.match(email)
        validpwd=b.match(pwd)
        validname= c.match(name)
        validaddress = d.match(address)
        geocode= URL + address
        result = requests.get(urlparse(geocode).geturl(),headers={"Authorization":"KakaoAK 230655e7cf44450d080665dc328e4dd2"})
        json_obj=result.json()

        x = json_obj['documents'][0]['x']
        y = json_obj['documents'][0]['y']

        #return JsonResponse({"x":x, "y": y,"email":email })
        dbemail=Users.objects.filter(email=email)
        if validemail and validpwd and validname and validaddress:
            if name and email and address and pwd:
                if dbemail:
                    return Response("Status 4002 : 이미 가입된 이메일 입니다.", status=status.HTTP_400_BAD_REQUEST)
                else:
                    Users.objects.create(email=email,
                                         pwd=bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"),
                                         name=name,
                                         address=address, x=x, y=y)
                    db = Users.objects.get(email=email)
                    token = jwt.encode({'user': db.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
                    Token.objects.create(token=token)
                    return Response("201 created", status=status.HTTP_201_CREATED)
            else:
                return Response("Status 4000 : 잘못된 접근입니다 .", status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response("Status 4004 : 잘못된 형식- 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET','PUT'], detail=False, url_path='password/reset')
    def password(self, request): #비밀번호 재설정, 비밀번호 찾기
        if request.method =='GET': #pwd 찾기
            email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
            headers = {
            'Authorization': 'Bearer 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',
            'Content-Type': 'application/json',
            }
            #return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": email})
            db = Users.objects.get(email=email)  # db에 저장되어있는 값 -db에서5agrvd@gmail.com
            if email:
                token = jwt.encode({'user': db.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
                #Token.objects.create(token=token)
                servertoken = Token.objects.get(token=token)
                #mail전송 - 토큰 정보 담음
                data1 = '{"personalizations": [{"to": [{"email": "5agrvd@gmail.com"}]}],"from": {"email": "5agrvd@gmail.com"},"subject": "reset password ","content": [{"type": "text/plain", "value": "'
                data2 = token +'   :password/reset/logininfo token sent  " }]}'
                data = data1 + data2
                requests.post(urlparse('https://api.sendgrid.com/v3/mail/send').geturl(), headers=headers, data=data)
                #return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": token})
                return Response("200 OK", status=status.HTTP_200_OK)
                #return Response("Status 4010 : 로그인 정보가 일치하지 않습니다.", status=status.HTTP_401_UNAUTHORIZED)
                #return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT': #pwd 변경
            email = request.POST.get('email', False) # postman에서 입력한 값 5agrvd@gmail.com
            pwd = request.POST.get('pwd',False)
            db = Users.objects.get(email=email)
            token = jwt.encode({'user': db.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
            servertoken=Token.objects.get(token=token)
            b = re.compile(
                '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!#%*?&])[A-Za-z\d$@$!%*?#&_\-~]{6,100}')  # pwd validation
            newpwd=b.match(pwd)
            #return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": token})
            if servertoken:
                if newpwd:
                    db.pwd=bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
                    db.save()
                    #requests.post(urlparse('https://api.sendgrid.com/v3/mail/send').geturl(), headers=headers, data=data)
                    # return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": token})
                    return Response("202 pwd재설정 완료...! Accepted", status=status.HTTP_202_ACCEPTED)
                else:
                    return Response("Status 4004 : 잘못된 형식- 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
    def create(self, request, *args, **kwargs):
        if request.method == 'POST':
            result = self.signup(request)
        return result

class HospitalViewSet(viewsets.ModelViewSet):
    queryset = Hospitals.objects.all() #hospitals에 있는 모든 데이터 다 가져옴.
    serializer_class = HospitalsSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(methods=['POST'], detail=False)
    def registerhospital(self, request): #병원정보등록
        name = request.POST.get('name',False) # postman에서 입력한 값
        tel = request.POST.get('tel',False)
        address = request.POST.get('address',False)
        opstatus = request.POST.get('status',False)
        if name and tel and address and opstatus:
            p = re.compile('^([ㄱ-ㅎㅏ-ㅣ가-힣]\s{0,}){1,100}|([a-zA-Z]\s{0,}){1,100}$')  # name validation
            q = re.compile('^(^0[0-9]{1,2})(-)?([0-9]{3,4})(-)?([0-9]{4})$') # tel validation
            r = re.compile('^([가-힣0-9]\s{0,}){6,200}|([a-zA-Z0-9]\s{0,}){6,200}$') #address validation
            s = re.compile('^(OPEN|CLOSED)$') #status validation
            validname = p.match(name)
            validtel = q.match(tel)
            validaddress = r.match(address)
            validstatus = s.match(opstatus)
            geocode = URL + address
            result = requests.get(urlparse(geocode).geturl(),
                                  headers={"Authorization": "KakaoAK 230655e7cf44450d080665dc328e4dd2"})
            json_obj = result.json()
            x = json_obj['documents'][0]['address']['x']
            y = json_obj['documents'][0]['address']['y']

            #id = request.GET.get('id',False)
            #return JsonResponse({'dddd': Hospitals.objects.filter(name=name)})
            if validname and validtel and validaddress and validstatus:

                Hospitals.objects.create(name=name, tel=tel, address=address, status=opstatus,x=x,y=y)
                return JsonResponse({"result": {"location" : "/hospitals/:hospitalId" } ,"success":'true' ,"errors":[] ,"messages": []},status=201)
                #return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
                #이미있는 병원등록경우...(?)
                #JsonResponse({'dddd': address})
        else:
            return Response("Status 4000 : 잘못된 형식.", status=status.HTTP_400_BAD_REQUEST)

            #{"result": {"location" : "/hospitals/:hospitalId" } },"success": true,"errors": [], "messages": []}
            #response = dict(name, tel, address, opstatus)
            #return JsonResponse({"result":{"name":name, "tel": tel, "address":address, "status":opstatus},"success":[],"msg":'true' },status=400)
    @action(methods=['POST'], detail=False)
    def excel(self,request):
        conn = pymysql.connect(host='localhost',user='on', password='okk0906',db='openedhospital',charset='utf8')
        try:
            with conn.cursor() as curs:
                sql="select * from hospitals"
                curs.execute(sql)
                rs=curs.fetchall()
                wb=Workbook()
                ws=wb.active
                ws.append(('id','name','tel','address','x','y','status' ,'createdAt','updatedAt'))
                for row in rs:
                    ws.append(row)

                wb.save('/Users/kwon-oh-eun/Documents/py3django/hospitalList.xlsx')
        finally:
            conn.close()
            wb.close()
        return Response("201 created", status=status.HTTP_201_CREATED)
    #내주변 열린 병원 보기
    @action(methods=['GET'],detail=False)
    def nearbyhospital(self, request): #내주변 열린 병원 보기
        name = request.POST.get('name', False)  # postman에서 입력한 값

        if name :#and tel and address and opstatus:
            #data = Hospitals.objects.create(name=name, tel=tel, address=address, status=opstatus)
            data = Hospitals.objects.get(name=name)
            tel=data.tel
            address=data.address
            opstatus=data.status
            return JsonResponse({'name': name,'tel':tel, 'address':address,'status':opstatus },status=202)
                #Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
            # return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
        else:
            #return JsonResponse({'dddd': data})
             Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET','PUT'],detail=False,url_path='hospitalid')
    def hospitalId(self, request): #병원상세보기
        if request.method == 'GET':
            name = request.POST.get('name', False)  # postman에서 입력한 값
            if name :
                data = Hospitals.objects.get(name=name)
                tel=data.tel
                address=data.address
                opstatus=data.status
                geocode = URL + address
                result = requests.get(urlparse(geocode).geturl(),
                                      headers={"Authorization": "KakaoAK 230655e7cf44450d080665dc328e4dd2"})
                json_obj = result.json()
                x = json_obj['documents'][0]['address']['x']
                y = json_obj['documents'][0]['address']['y']
                #data.loads()
                return JsonResponse({"result": {"location" : "/hospitals/:hospitalid" ,
                                                "name":name, "tel":tel,"address":address,"status":opstatus,"x":x,"y":y,
                                                } ,"success":'true' ,"errors":[] ,"messages": []},status=201)
                    #Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
                # return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
            else:
                Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)
        elif request.method == 'PUT': #112.진료거부병원 정보 변경.
            name = request.POST.get('name', False)  # postman에서 입력한 값 (변경할 병원)
            afterstatus = request.POST.get('status', False)
            hospitalobj= Hospitals.objects.get(name=name)
            beforestatus = hospitalobj.status
            if name and afterstatus != beforestatus:
                hospitalobj.status = afterstatus
                hospitalobj.save()
                return JsonResponse(
                    {"result": {"location": "/hospitals/:hospitalId"}, "success": 'true', "errors": [], "messages": []},
                    status=200)
            #병원id넣어야 할듯...?
            elif afterstatus == beforestatus:
                return Response("Status 4005 : 현재와 같은 상태(OPEN|CLOSED) 입니다..", status=status.HTTP_400_BAD_REQUEST)
            return Response("Status 4000 : 잘못된 요청입니다 .", status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        if request.method == 'POST':
            result = self.registerhospital(request)
        return result

    def list(self, request, *args, **kwargs):
        if request.method == 'GET':
            result = self.nearbyhospital(request)
        return result

    def update(self, request, pk=None,*args, **kwargs):
        if request.method == 'PUT':
            result = self.hospitalId(request)
        return result

class HEViewSet(viewsets.ModelViewSet):
    queryset = Hospitaledithistories.objects.all()
    serializer_class = HESerializer
    permission_classes = [permissions.IsAuthenticated]



class TokenViewSet(viewsets.ModelViewSet):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    permission_classes = [permissions.IsAuthenticated]

# Create your views here.
