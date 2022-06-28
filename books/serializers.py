from .models import *
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields='__all__'

class BooksSerializer(serializers.ModelSerializer):
    class Meta:
        model=Books
        fields='__all__'


class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model=Users
        fields='__all__'



