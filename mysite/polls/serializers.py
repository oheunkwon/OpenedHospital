from rest_framework import serializers 
from .models import Users, Hospitals, Hospitaledithistories, Token

class UsersSerializer(serializers.HyperlinkedModelSerializer):
	class Meta: 
		model = Users
		fields=['url','id','uid','email','pwd','name','address','x','y']
		
class HospitalsSerializer(serializers.HyperlinkedModelSerializer):
	class Meta: 
		model = Hospitals
		fields=['url','id','name','tel','address','status','x','y']
		
class HESerializer(serializers.HyperlinkedModelSerializer):
	class Meta: 
		model = Hospitaledithistories
		fields=['url','id','userid','hospitalid','status']
		
class TokenSerializer(serializers.HyperlinkedModelSerializer):
	class Meta: 
		model = Token
		fields=['url','id','userid','token','expiredAt','createdAt','updatedAt']

