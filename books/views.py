from django.shortcuts import render,redirect
from django.contrib import messages
from rest_framework.decorators import authentication_classes,permission_classes
from .models import *
from django.contrib.auth import authenticate,login,logout
#imported for sending email using django
from django.core.mail import EmailMessage,send_mail
from django.conf import settings
#imported for sending email using django
import smtplib
from email.message import EmailMessage
from django.contrib.auth.models import User
# imported for API
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets
from .serializers import *
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import BaseAuthentication,SessionAuthentication
from django.shortcuts import get_object_or_404
import jwt









# Create your views here.
def home(request):
    # if 'user' in request.session:
    #     user = request.session['user']
        return render(request, 'home.html')




##sending dynamic email(1)
def send_dynamic_email_registration(toemail,username):
    print("in email func")
    EMAIL_ADDRESS= settings.EMAIL_HOST_USER
    EMAIL_PASSWORD= settings.EMAIL_HOST_PASSWORD
    argument={
        "username":username
    }

    msg=EmailMessage()
    msg['Subject']="thanks for registering"
    msg['From']=EMAIL_ADDRESS
    msg['To']=toemail
    html_content='<p>This is an <strong>important</strong> message.</p>'
    # message = get_template('email(registration).html').render(argument)
    # print(message)
    # msg.set_content("Hi " +username+",Thanks for registering into JBIET Library System ")
    msg.set_content(html_content, "text/html")
    # msg.add_alternative(html_content, "text/html")
#     msg.add_alternative("""/
#     <!DOCTYPE html>
# <html>
#     <head>
#         <title>Email</title>
#         <meta name="viewport">
#         <meta charset="UTF-8">
#         <meta content="intial-scale=1.0,width=device-width">
#     </head>
# <body>
#     Hi,username
#     It's great to have you as a user
#
#     Thank you,for registering into JBIET Library Management System
#
# </body>
# </html>
# """,subtype='html')
    msg.content_subtype="text"
    with smtplib.SMTP_SSL('smtp.gmail.com',465) as smtp:
        smtp.login(EMAIL_ADDRESS,EMAIL_PASSWORD)
        smtp.send_message(msg)


#registration using django authentication
def register(request):
    if request.method=='POST':
        print("request method post")
        username=request.POST["username"]
        userid=request.POST["userid"]
        email=request.POST["email"]
        password1=request.POST["pwd1"]
        password2=request.POST["pwd2"]
        role=request.POST["role"]
        print(username,email,password1,password2,role)
        # validation
        if User.objects.filter(id=userid).exists():
            print("userid error")
            messages.error(request,"userid already taken")
            return render(request,"registerpage.html")
        elif User.objects.filter(username=username).exists():
            print("username_error")
            messages.error(request,"User already taken")
            return render(request, "registerpage.html")
        elif User.objects.filter(email=email).exists():
            print("email error")
            # return render(request,"register.html",{"email_error":"email already taken"})
            messages.error(request,"email already taken")
            return render(request, "registerpage.html")
        elif password1!=password2:
            print("passwords not matching")
            messages.error(request,"passwords not matching")
            return render(request,"registerpage.html")
        else:
            # send_dynamic_email_registration(email,username)
            print("email func working")
            # assign role either student/staff to the user
            # user = User.objects.get(username=username)
            # print(user)
            position = ExtendDjangoUser(role=role)
            # position = ExtendDjangoUser(username=user, role=role)
            position.save();
            print("user created")
            user = User.objects.create_user(id=userid,username=username,email=email,password=password1)

            user.save();
            return redirect('/login')
    # groups=Group.objects.all()
    # print("groups:",groups)
    print("groups")
    return render(request,'registerpage.html')

#login with django authentication
def userlogin(request):
    if request.method=='POST':
        username=request.POST["username"]
        password=request.POST["password"]
        print(username)
        print(password)
        user=authenticate(username=username,password=password)
        # user.IsAuthenticated
        if user is not None:
            print("valid user")
            if user.is_active:
            # user_id=User.objects.get()
            #getting the role of the user by using id of the user which is automatically created by django
            # person=ExtendDjangoUser.objects.get(username=user.id)
            # print(user.id)
            # print(person.role)
            # if person.role==Staff:
            # written for login using django
                login(request,user)
                # messages.success(request,"successfully logged In")
                return redirect("/viewbooks")
        else:
            print("invalid username and password")
            messages.error(request,"invalid username and password")
            return render(request, "home.html")
    else:
         return redirect("/")


def send_dynamic_email_changepwd(request,toemail,username):
    from django.core.mail import EmailMultiAlternatives

    subject, from_email, to = 'hello', 'vinaymadugula20@gmail.com', 'vinaymadugula20@gmail.com'
    text_content = 'This is an important message.'
    html_content = '<p>This is an <strong>important</strong> message.</p>'
    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
def changepwd(request):
    if request.method=="POST":
        username=request.POST["name_username"]
        print(username)
        if User.objects.filter(username=username).exists():
            user=User.objects.get(username=username)
            email=user.email
            id=user.id
            print(user)
            print(id)
            print(email)
            forpwd=Forgetpwd()
            forpwd.token=123
            print(forpwd.token)
            forpwd.user_id=user
            forpwd.save()
            print(forpwd)
            send_dynamic_email_changepwd(request,email,username)
            print("email sent")
            return redirect("/viewbooks")

        else:
            return render(request,"changepwd.html",{"username_error":"Username doesn't exist"})
    else:
        return render(request,"changepwd.html",)


# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
def userlogout(request):
        logout(request)
        # messages.success(request,"Succesfully Logged Out" )
        return redirect("/")
        # auth.logout(request)


# @authentication_classes([JWTAuthentication],)
# @permission_classes([IsAuthenticated],)
#viewing books
def view(request):

    books=Books.objects.all()
    print('books',books)
    return render(request,'view_books.html',{"books":books})

# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
#editing/updating books
def edit(request,id):

    if id:
        book_obj=Books.objects.get(id=id)
        if request.method=='POST':
            username=request.POST["username"]
            print(username)
            book_obj.username=username
            userid=id
            # userid=request.POST["userid"]
            # print(userid)
            # book_obj.userid=userid
            bookid=request.POST["bookid"]
            print(bookid)
            book_obj.book_id=bookid
            bookname=request.POST["bookname"]
            book_obj.book_name=bookname
            # book author is removed in new version
            # bookauthor=request.POST["book_author"]
            # book_obj.book_author=bookauthor
            book_obj.save()
            return redirect('/viewbooks')
        return render(request, 'edit_book.html', {'book': book_obj})
    print("id",id)
    return render(request,'edit_book.html',{'books':books})

# @authentication_classes([JWTAuthentication])
# @permission_classes([IsAuthenticated])
#deleting books
def delete(request,id):
    print("delete id",id)
    if id:
        book_obj = Books.objects.get(id=id)
        print('book_obj',book_obj)
        book_obj.delete()
        return redirect('/viewbooks')
    return render(request,"delete_book.html")


#adding book
def books(request):
    if request.method=='POST':
        try:
            user_name=request.POST["username"]
            print(user_name)
            # userid = request.POST["userid"]
            # print(userid)
            # if User.objects.filter(id=userid).exists():
            #     user_obj=User.objects.get(id=userid)
            if User.objects.filter(username=user_name).exists():
                    # if user_obj.username==user_name:
                        books_obj = Books()
                        # books_obj.userid = userid
                        books_obj.username=user_name
                        bookid=request.POST["bookid"]
                        books_obj.book_id=bookid
                        print("bookid", bookid)
                        # book author has been removed in new version
                        # bookauthor=request.POST["book_author"]
                        # books_obj.book_author = bookauthor
                        # print("bookauthor",bookauthor)
                        bookname=request.POST["bookname"]
                        books_obj.book_name=bookname
                        print("bookname",bookname)
                        print("it's a post method")
                        books_obj.save()
                        return redirect('/viewbooks')
                    # else:
                    #     messages.error(request,"userid and username does not match")
                    #     return render(request, "registerpage.html")
            else:
                    messages.error(request,"username doesn't exist")
                    return render(request,"registerpage.html")
            # else:
            #      messages.error(request,"userid doesn't exist")
            #      return render(request,"registerpage.html")
        except Exception as e:
            print("Error on add books",e)
            return render(request, "view_books.html",{"error":e})
    else:
        return render(request,"add_books.html")



#personal info

#using id
# def personal_info(request,id):
#     user=User.objects.filter(id=id)
#     print("got user datails")
#     return render(request,"personal_info.html",{"user":user})

#using self
# def personal_info(request,self):
#     user=self.request.user
#     user_obj=User.objects.filter(user=user)
#     return render(request, "personal_info.html", {"user": user_obj})

# using request.user
def personal_info(request):
    user_obj=request.user
    if user_obj.is_authenticated:
        return render(request, "personal_info.html", {"user": user_obj})
    else:
        messages.error(request,"something went wrong,try again!")
        return render(request,"home.html")




def personal_info_change(request):
    if request.method=='POST':
        try:
            old_userid=request.POST["old_userid"]
            if User.objects.filter(id=old_userid).exists():
                old_username=request.POST["old_username"]
                if User.objects.filter(username=old_username).exists():
                    user_obj=User.objects.get(id=old_userid)
                    if user_obj.username==old_username:
                        old_email=request.POST["old_email"]
                        if User.objects.filter(email=old_email).exists():
                            old_password=request.POST["old_password"]
                            if User.objects.filter(password=old_password).exists():
                                new_password=request.POST["new_password"]
                                new_password2=request.POST["re-enter_new_password"]
                                if new_password==new_password2:
                                    new_userid=request.POST["new_userid"]
                                    user_obj.id=new_userid
                                    new_username=request.POST["new_username"]
                                    user_obj.username=new_username
                                    new_email=request.POST["new_email"]
                                    user_obj.email=new_email
                                    user_obj.password=new_password
                                    user_obj.save()
                                    return render(request,"personal_info.html")
                                else:
                                    messages.error("passwords not matching")
                                    return render(request,"personal_info_change.html")
                            else:
                                messages.error(request,"old password does not exist")
                                return render(request, "personal_info_change.html")
                        else:
                            messages.error(request, "email does not exist")
                            return render(request, "personal_info_change.html")
                    else:
                        messages.error(request, "username and userid does not of same user")
                        return render(request, "personal_info_change.html")
                else:
                    messages.error(request, "username does not exist")
                    return render(request, "personal_info_change.html")
            else:
                messages.error(request, "userid does not exist")
                return render(request, "personal_info_change.html")
        except Exception as e:
            messages.error("reload the page and try again")
            return render(request,"personal_info_change.html")
    return render(request,"personal_info_change.html")


# API viewsets
class RegisterViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()
    serializer_class = Users

    def list(self, request):
        try:
            queryset = User.objects.all()
            serializer = UserSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            print("error",e)
            return Response({'message','something went wrong try again'},status=status.HTTP_404_NOT_FOUND)

    def create(self, request, *args):
        # print("in create method")
        try:
            username = request.data['email']
            print("username:",username)
            password = request.data['password']
            print("password:",password)
            email = request.data['email']
            print("email", email)
            try:
                user = User.objects.create_user(username, email=request.data['email'], password=request.data['password'])
                user.save()
                return Response({'success': {'message': 'User created successfully !'}}, status=status.HTTP_200_OK)
            except Exception as e:
                print("user exist exception",e)
                return Response({'error': {'message': 'User Already existing'}}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("error:",e)
            return Response({'error': {'message': 'something went wrong'}}, status=status.HTTP_400_BAD_REQUEST)


class LogInViewSet(viewsets.ModelViewSet):

    def create(self, request):
        try:
            username = request.data['username']
            # print('username:', username)
            # email = request.data['email']
            password = request.data['password']
            # print('password:', password)
            try:
                user = authenticate(username=request.data['username'], password=request.data['password'])
                # print("user:",user)
                # user = authenticate(username=request.data['email'], password=request.data['password'])
                userid = user.id
                # print("userid",userid)
                username = user.username
                # print("username",username)
                # password = user.password
                # print("password",password)
                payload = {
                    'id': userid,
                    'username': username,
                    # 'password': password
                }
                # print("payload",payload)
                key = 'secret'
                token = jwt.encode(payload, key, algorithm='HS256')
                # print("token",token)
                response = Response()
                response.set_cookie(key='jwt', value=token, httponly=True)
                response.data = {
                                    'token': token,
                                    'success': 'user logged-in sucessfully'
                                }
                return response
            except Exception as e:
                return Response({'error': 'Invalid Credentials'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error':'username, email, password must be entered'}, status=status.HTTP_400_BAD_REQUEST)


class UserBooks(APIView):
    # queryset = Books.objects.all()
    # serializer_class = BooksSerializer(queryset, many=True)

    def get(self, request):
        try:
            token = request.COOKIES.get('jwt')
            key = 'secret'
            payload = jwt.decode(token,key,algorithms=['HS256'])
            user = User.objects.get(pk= payload['id'])
            print(user)
            queryset = Books.objects.filter(user=user)
            print(queryset)
            serializer = BooksSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            print(e)
            return Response({"error":"log-in and try again"},status=status.HTTP_400_BAD_REQUEST)




# class BooksViewset(viewsets.ModelViewSet):
#     serializer_class = BooksSerializer
#     queryset = Books.objects.all()
    # authentication_classes([SessionAuthentication, BaseAuthentication])
    # permission_classes([IsAuthenticated])

    # def list(self, request, *args):
    #     queryset = Books.objects.all()
    #     serializer = BooksSerializer(queryset, many=True)
    #     return Response(serializer.data)
    #
    # def create(self, request, *args):
    #     allowed_fields= ['username', 'userid', 'bookid', 'bookname']
    #     mandatory_fields= ['userid', 'bookid', 'bookname']
    #     temp=set(mandatory_fields) - set(allowed_fields)
    #     if len(temp):
    #         wrong_fields=','.join(field for field in temp)
    #         return Response({'error': '{} fields are mandatory'.format(wrong_fields)},status=status.HTTP_400_BAD_REQUEST)
    #     input_keys = request.data.keys()
    #     user_name= request.data['username']
    #     if User.objects.filter(username=user_name).exists():
    #         book_obj= Books()
    #         try:
    #             if 'username' in request.data:
    #                 book_obj.username = user_name
    #             if 'userid' in request.data:
    #                 book_obj.userid = request.data['userid']
    #             if 'bookid' in request.data:
    #                 book_obj.book_id = request.data['bookid']
    #             if 'bookname' in request.data:
    #                 book_obj.book_name = request.data['bookname']
    #             book_obj.save()
    #             return Response({'success': 'Book Saved'},status=status.HTTP_200_OK)
    #         except Exception as e:
    #             return Response({'error': 'invalid credentials'},status=status.HTTP_400_BAD_REQUEST)
    #
    #     else:
    #         return Response({'error': 'wrong username'},status=status.HTTP_400_BAD_REQUEST)
    #
    # def retrieve(self, request, pk=None):
    #     try:
    #         queryset = Books.objects.all()
    #         book = get_object_or_404(queryset, pk=pk)
    #         serializer = BooksSerializer(book)
    #         return Response(serializer.data)
    #     except Exception as e:
    #         return Response({"error": "Book doesn't exist"}, status=status.HTTP_404_NOT_FOUND)
    #
    # def destroy(self, request,pk=None):
    #     try:
    #         queryset=Books.objects.all()
    #         book= get_object_or_404(queryset, pk=pk)
    #         if book:
    #             book.delete()
    #         return Response({'success': "Book deleted succesfully"}, status=status.HTTP_200_OK)
    #     except Exception as e:
    #         return Response({'error': 'Book bot found,try again'},status=status.HTTP_400_BAD_REQUEST)

































