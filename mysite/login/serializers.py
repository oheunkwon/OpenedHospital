from rest_framework import serializers
from .models import Users

class UsersSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = Users
		fields=['url','id','uid','email','pwd','name','address','x','y']