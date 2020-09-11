import re
from urllib.parse import urlparse
from django.http import HttpResponse, JsonResponse
#from django.views import View
from rest_framework import viewsets, permissions, status
import jwt
import bcrypt
from openpyxl import Workbook
import pymysql
import requests
from rest_framework.decorators import action
from rest_framework.response import Response
from mysite.settings import SECRET_KEY
from .serializers import UsersSerializer, HospitalsSerializer, HESerializer, TokenSerializer
from .models import Users, Hospitals, Hospitaledithistories, Token
# from django.core.mail import send_mail
# import json
ERR_CODE_4000 = "잘못된 요청입니다.{fieldname}"
ERR_CODE_4002 = "{email}은(는) 이미 가입된 이메일 입니다."
ERR_CODE_4003 = "주소가 잘못되었거나 존재하지 않습니다."
ERR_CODE_4004 = "{field_name}을 입력해주세요."
ERR_CODE_4005 = "{hospitals.name}은 이미 {status} 된 병원입니다."
ERR_CODE_4010 = "로그인 정보가 일치하지 않습니다."
ERR_CODE_4011 = "존재하지 않는 이메일 입니다."
ERR_CODE_4012 = "만료되었습니다 ."
ERR_CODE_4030 = "권한이 없습니다."
ERR_CODE_4040 = "존재하지 않는 리소스 입니다."
ERR_CODE_4041 = "존재하지 않는 {hospital_id} 입니다."
ERR_CODE_5000 = "요청을 처리할 수 없습니다."

EMAIL_RGX = '^[\w\-]+@(?:(?:[\w\-]{2,}\.)+[a-zA-Z]{2,})$'
PWD_RGX = '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!#%*?&])[A-Za-z\d$@$!%*?#&_\-~]{6,100}'
NAME_RGX = '^([ㄱ-ㅎㅏ-ㅣ가-힣]\s{0,}){1,100}|([a-zA-Z]\s{0,}){1,100}$'
ADDR_RGX = '^([가-힣0-9]\s{0,}){6,200}|([a-zA-Z0-9]\s{0,}){6,200}$'
TEL_RGX = '^(^0[0-9]{1,2})(-)?([0-9]{3,4})(-)?([0-9]{4})$'
STATUS_RGX = '^(OPEN|CLOSED)$'
APP_KEY = ''
URL = 'https://dapi.kakao.com/v2/local/search/address.json?query='
"""
열린병원 API 구현.
"""


class UsersViewSet(viewsets.ModelViewSet):
    """
    users 테이블에서 데이터 가져와 사용.
    user 테이블 의 뷰셋.
    """
    queryset = Users.objects.all()  # user에 있는 모든 데이터 다 가져옴.
    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated]  # 인증된 사용자에게만 액세스 허용

    # 012.로그인 ~~~users/login/
    @action(methods=['POST'], detail=False)
    def login(self, request):
        """
        012. 로그인
        :email: 불러올 이메일
        :pwd:불러올 패스워드 - pwd를 암호화 하여 db에 저장되어 있는 암호화된 값과 비교한다. errcode 4010
        -email/pwd 하나라도 채워지지 않았을 경우 errcode 4004
        """
        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111
        if email and pwd:
            db_email = Users.objects.get(email=email)  # db에 저장되어있는 값 -db에서5agrvd@gmail.com
            if bcrypt.checkpw(pwd.encode('UTF-8'), db_email.pwd.encode('UTF-8')):
                return Response("202 Accepted", status=status.HTTP_202_ACCEPTED)
            return Response(ERR_CODE_4010, status=status.HTTP_401_UNAUTHORIZED)
        return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)

    # v1/users/
    @action(methods=['POST'], detail=False)
    def signup(self, request):  # 회원가입
        """
        011. 회원가입
        :email,pwd,address,name: 불러올 이메일, 패스워드, 주소, 이름
        :coord_x,coord_y: 좌표값. address 로부터 좌표값을 변환하여 저장.
        :regex_{email|pwd|name|addr} : 정규식 체크
               -email, pwd 하나라도 채워지지 않았을 경우 errcode 4004
        :db_email: 생성하려는 email 이 이미 데이터베이스 내에 존재하는가 체크 위한 변수. 이미 존재한다면 True 반환.
        -return: 형식 맞지않는 값 입력시 errcode 4004 / 값이 들어오지 않은 경우 errcode 4000
        """
        email = request.POST.get('email', False)  # postman 에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)  # 11111
        name = request.POST.get('name', False)
        address = request.POST.get('address', False)
        regex_email = re.compile(EMAIL_RGX)  # email validation
        regex_pwd = re.compile(PWD_RGX)  # pwd valid
        regex_name = re.compile(NAME_RGX)  # name validation
        regex_addr = re.compile(ADDR_RGX)  # address validation
        # return JsonResponse({'dddd': address, 'pwd': token})
        valid_email = regex_email.match(email)
        valid_pwd = regex_pwd.match(pwd)
        valid_name = regex_name.match(name)
        valid_address = regex_addr.match(address)
        geocode = URL + address
        result = requests.get(urlparse(geocode).geturl(),
                              headers={"Authorization": "KakaoAK 230655e7cf44450d080665dc328e4dd2"})
        json_obj = result.json()
        coord_x = json_obj['documents'][0]['x']
        coord_y = json_obj['documents'][0]['y']
        db_email = Users.objects.filter(email=email)
        if valid_email and valid_pwd and valid_name and valid_address:
            if name and email and address and pwd:
                if db_email:
                    return Response(ERR_CODE_4002, status=status.HTTP_400_BAD_REQUEST)
                else:
                    Users.objects.create(email=email,
                                         pwd=bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"),
                                         name=name,
                                         address=address, x=coord_x, y=coord_y)
                    db_email = Users.objects.get(email=email)
                    token = jwt.encode({'user': db_email.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
                    Token.objects.create(token=token)
                    return Response("201 created", status=status.HTTP_201_CREATED)
            return Response(ERR_CODE_4000, status=status.HTTP_400_BAD_REQUEST)
        return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET'], detail=False, url_path='password/find')
    def password(self, request):  # 비밀번호 재설정, 비밀번호 찾기
        """
        013. 비밀번호 찾기
        -db에 저장된 email 토큰과 값이 같은 것이 있으면 True
        -없으면 errcode 4012
        """

        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        headers = {
            'Authorization': 'Bearer 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',
            'Content-Type': 'application/json',
        }
        # return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": email})
        db_email = Users.objects.get(email=email)  # db에 저장되어있는 값 -db에서5agrvd@gmail.com
        if email:
            token = jwt.encode({'user': db_email.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
            Token.objects.get(token=token)
            # mail전송 - 토큰 정보 담음
            data1 = '{"personalizations": [{"to": [{"email": "5agrvd@gmail.com"}]}],"from": ''{"email": ''"5agrvd@gmail.com"},"subject": "reset password ","content": ''[{"type": "text/plain", ''"value": " '
            data2 = '   :password/reset/login info token sent  " }]}'
            data = data1 + data2
            requests.post(urlparse('https://api.sendgrid.com/v3/mail/send').geturl(), headers=headers, data=data)
            # return JsonResponse({"비밀번호 재설정 링크 이메일 전송 완료.....": token})
            return Response("200 OK", status=status.HTTP_200_OK)
        return Response(ERR_CODE_4012, status=status.HTTP_401_UNAUTHORIZED)

    @action(methods=['PUT'], detail=False, url_path='password/reset')
    def password_reset(self, request):  # 비밀번호 재설정, 비밀번호 찾기
        """
        014. 비밀번호 재설정
        """
        email = request.POST.get('email', False)  # postman에서 입력한 값 5agrvd@gmail.com
        pwd = request.POST.get('pwd', False)
        db_email = Users.objects.get(email=email)
        token = jwt.encode({'user': db_email.email}, SECRET_KEY, algorithm='HS256').decode('UTF-8')
        server_token = Token.objects.get(token=token)
        regex_pwd = re.compile(PWD_RGX)  # pwd validation
        new_pwd = regex_pwd.match(pwd)
        if server_token:
            if new_pwd:
                db_email.pwd = bcrypt.hashpw(pwd.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
                db_email.save()
                return Response("202 pwd재설정 완료...! Accepted", status=status.HTTP_202_ACCEPTED)
            return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)
        return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        if request.method == 'POST':
            result = self.signup(request)
        return result


class HospitalViewSet(viewsets.ModelViewSet):
    queryset = Hospitals.objects.all()
    serializer_class = HospitalsSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(methods=['POST'], detail=False)
    def register_hospital(self, request):  # 병원정보등록
        """
        111. 진료거부 병원 등록
        """
        name = request.POST.get('name', False)  # postman 에서 입력한 값
        tel = request.POST.get('tel', False)
        address = request.POST.get('address', False)
        op_status = request.POST.get('status', False)
        if name and tel and address and op_status:
            regex_name = re.compile(NAME_RGX)  # name validation
            regex_tel = re.compile(TEL_RGX)  # tel validation
            regex_addr = re.compile(ADDR_RGX)  # address validation
            regex_status = re.compile(STATUS_RGX)  # status validation
            valid_name = regex_name.match(name)
            valid_tel = regex_tel.match(tel)
            valid_address = regex_addr.match(address)
            valid_status = regex_status.match(op_status)
            geocode = URL + address
            result = requests.get(urlparse(geocode).geturl(),
                                  headers={"Authorization": "KakaoAK 230655e7cf44450d080665dc328e4dd2"})
            json_obj = result.json()

            coord_x = json_obj['documents'][0]['x']
            coord_y = json_obj['documents'][0]['y']

            if valid_name and valid_tel and valid_address and valid_status:
                Hospitals.objects.create(name=name, tel=tel, address=address, status=op_status, x=coord_x, y=coord_y)
                return JsonResponse(
                    {"result": {"location": "/hospitals/:hospitalId"}, "success": 'true', "errors": [], "messages": []},
                    status=201)
                # return Response("Status 4004 : 다시 입력해 주세요.", status=status.HTTP_400_BAD_REQUEST)

            return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)
        return Response(ERR_CODE_4000, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False)
    def excel(self):
        """
        131. 전체 리스트 다운로드
        """
        conn = pymysql.connect(host='localhost', user='on', password='okk0906', db='openedhospital', charset='utf8')
        try:
            with conn.cursor() as curs:
                sql = "select * from hospitals"
                curs.execute(sql)
                result = curs.fetchall()
                work_book = Workbook()
                work_state = work_book.active
                work_state.append(('id', 'name', 'tel', 'address', 'x', 'y', 'status', 'createdAt', 'updatedAt'))
                for row in result:
                    work_state.append(row)

                work_book.save('/Users/kwon-oh-eun/Documents/py3django/hospitalList.xlsx')
        finally:
            conn.close()
            work_book.close()
        return Response("201 created", status=status.HTTP_201_CREATED)

    # 열린 병원 보기
    @action(methods=['GET'], detail=False)
    def nearby_hospital(self, request):  # 열린 병원 보기
        """
        121. 병원 검색
        이름 검색하여 해당하는 병원 보기.
        """
        name = request.POST.get('name', False)  # postman에서 입력한 값

        if name:  # and tel and address and opstatus:
            # data = Hospitals.objects.create(name=name, tel=tel, address=address, status=opstatus)
            data = Hospitals.objects.get(name=name)
            tel = data.tel
            address = data.address
            op_status = data.status
            return JsonResponse({'name': name, 'tel': tel, 'address': address, 'status': op_status}, status=202)

        return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET', 'PUT'], detail=False, url_path='hospitalid')
    def hospital_id(self, request):  # 병원상세보기
        """
        123. 병원상세보기
        """
        if request.method == 'GET':
            name = request.POST.get('name', False)  # postman에서 입력한 값
            if name:
                data = Hospitals.objects.get(name=name)
                tel = data.tel
                address = data.address
                op_status = data.status
                geocode = URL + address
                result = requests.get(urlparse(geocode).geturl(),
                                      headers={"Authorization": "KakaoAK 230655e7cf44450d080665dc328e4dd2"})
                json_obj = result.json()
                coord_x = json_obj['documents'][0]['address']['x']
                coord_y = json_obj['documents'][0]['address']['y']
                # data.loads()
                return JsonResponse({"result": {"location": "/hospitals/:hospitalid",
                                                "name": name, "tel": tel, "address": address, "status": op_status,
                                                "x": coord_x, "y": coord_y,
                                                }, "success": 'true', "errors": [], "messages": []}, status=201)

            return Response(ERR_CODE_4004, status=status.HTTP_400_BAD_REQUEST)
        else:  # 112.진료거부병원 정보 변경.
            name = request.POST.get('name', False)  # postman 에서 입력한 값 (변경할 병원)
            after_status = request.POST.get('status', False)
            hospital_obj = Hospitals.objects.get(name=name)
            before_status = hospital_obj.status
            if name and after_status != before_status:
                hospital_obj.status = after_status
                hospital_obj.save()
                return JsonResponse(
                    {"result": {"location": "/hospitals/:hospitalId"}, "success": 'true', "errors": [], "messages": []},
                    status=200)
            return Response(ERR_CODE_4005, status=status.HTTP_400_BAD_REQUEST)
        return Response(ERR_CODE_4000, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        if request.method == 'POST':
            result = self.register_hospital(request)
        return result

    def list(self, request, *args, **kwargs):
        if request.method == 'GET':
            result = self.nearby_hospital(request)
        return result

    def update(self, request, pk=None, *args, **kwargs):
        if request.method == 'PUT':
            result = self.hospital_id(request)
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
