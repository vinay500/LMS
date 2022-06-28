from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Books(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    # username=models.CharField(max_length=30,null=True)
    book_id=models.IntegerField(primary_key=True)
    book_name=models.CharField(max_length=30)
    # book_author=models.CharField(max_length=30)

    def __str__(self):
        return self.book_name


class Users(models.Model):
    username=models.CharField(max_length=30)
    email=models.EmailField(max_length=30)
    password=models.CharField(max_length=30)

    def __str__(self):
        return self.username


class ExtendDjangoUser(models.Model):
    username = models.ForeignKey(User, on_delete=models.CASCADE,null=True)
    role=models.CharField(max_length=10,null=True)

class Forgetpwd(models.Model):
    user_id=models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    token=models.IntegerField(unique=True)
