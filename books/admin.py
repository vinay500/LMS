from django.contrib import admin
from .models import Books,ExtendDjangoUser,Forgetpwd

# Register your models here.
admin.site.register(Books)
admin.site.register(ExtendDjangoUser)
admin.site.register(Forgetpwd)

