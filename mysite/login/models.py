from django.db import models

# Create your models here.
class Users(models.Model):

    email = models.CharField(max_length=255, blank=True, null=True)
    pwd = models.CharField(max_length=255, blank=True, null=True)


    class Meta:
        managed = False
        db_table = 'Users'
