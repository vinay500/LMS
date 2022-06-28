from django.urls import path,include
from django.contrib import admin
from django.conf.urls import url
from . import views
from .views import *
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

router = DefaultRouter()

# router.register(r'books', BooksViewset, 'books')
router.register(r'register', RegisterViewSet, 'UserRegsiter')
router.register(r'login', LogInViewSet, 'login')
# router.register(r'books', BooksViewset, 'books')


urlpatterns=[
    path("router/",include(router.urls)),
    path("",views.home,name="home"),
    path("home",views.home,name="home"),
    path("addbooks",views.books,name="books"),
    path("viewbooks",views.view,name="view"),
    path("deletebook/<int:id>",views.delete,name="delete"),
    path("editbook/<int:id>",views.edit,name="edit"),
    path("registration",views.register,name="register"),
    path("login",views.userlogin,name="name_login"),
    path("changepwd",views.changepwd,name="changepwd"),
    path("logout",views.userlogout,name="name_logout"),
    path("personal_info",views.personal_info,name="personal_info"),
    path("personal_info_change",views.personal_info_change,name="personal_info_change"),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('userbooks/', UserBooks.as_view(), name='user_books'),



]