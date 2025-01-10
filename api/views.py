from django.shortcuts import render
from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from datetime import datetime, timedelta
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from django.contrib.auth import authenticate
from .filters import *
from django_filters.rest_framework import DjangoFilterBackend

import uuid
from django.core.mail import send_mail
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account
domain="http://192.168.50.208:8000"
def sendMail(subject,message,email):
    send_mail(subject,message,'aupulse@gmail.com',email)
class ForgotPasswordView(APIView):
    def post(self,request):
        serializer=ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user=User.objects.get(username=serializer.data["username"].upper())
                token=uuid.uuid4()
                PasswordChange.objects.filter(user=user).delete()
                sendMail("Password Reset",f"Dear {user.username} click below link to reset password\n{domain}/resetpassword/?token={token}",[user.email])
                PasswordChange(user=user,token=token).save()
                return Response({"msg":"Mail sent"},status=status.HTTP_200_OK)
            except:
                return Response({"error":"No user exists with username"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return  Response({"error":"Enter valid details"}, status=status.HTTP_404_NOT_FOUND)
class ChangePasswordView(APIView):
    authentication_classes=[TokenAuthentication]
    def get(self,r):
        user=r.auth.user
        token=uuid.uuid4()
        PasswordChange.objects.filter(user=user).delete()
        sendMail("Password Reset",f"Dear {user.username} click below link to reset password\n{domain}/resetpassword/?token={token}",[user.email])
        PasswordChange(user=user,token=token).save()
        return Response({"msg":"Mail sent"},status=status.HTTP_200_OK)

class LoginView(APIView):
    def post(self,r):
        serializer = LoginSerializer(data=r.data)
        if serializer.is_valid():
            try:
                user=User.objects.get(email=serializer.data["email"].lower())
                user=authenticate(username=user.username,password=serializer.data['password'])
                if user is not None:
                    if Verification.objects.filter(user=user,is_verified=True):
                        token,created=Token.objects.get_or_create(user=user)
                        return Response({"token":token.key,"created":created,"status":True},status=status.HTTP_200_OK)
                    else:
                        return  Response({"error":"Email not verified"},status=status.HTTP_400_BAD_REQUEST)
                return  Response({"error":"Invalid Credentials"},status=status.HTTP_400_BAD_REQUEST)
            except:
                return Response({"error":"User not found with this email"},status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
class SignupView(APIView):
    def post(self,r):
        serializer = UserSerializer(data=r.data)
        if serializer.is_valid():
            user=serializer.save()
            token=uuid.uuid4()
            Verification(user=user,token=token).save()
            sendMail("Email Verification",f'Dear {user.username} click below link to verify your email\n{domain}/verifyemail/?token={token}',[user.email])
            # token,created=Token.objects.get_or_create(user=user)
            return Response({"status":True},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class FCMv1Sender:
    PROJECT_ID = 'fixitnow-698b4'
    SERVICE_ACCOUNT_JSON = {
                        "type": "service_account",
                        "project_id": "fixitnow-698b4",
                        "private_key_id": "6eed46c69d6289dd8bd2387f1ef2b3af36ad1b65",
                        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDbw5GbKAyBDKC\nSUOSonuECiZtHqcOvdzBpJKIKfLwX0egS3EpvRtt2K+V76TWxvsRa2CGjsefMXiy\nCDKHrFfiGytcDEG+lDFMzKNa8K56MD6uE6X0IC/EADYH6emohoTAkNOdJ5lyUSwz\n6NaW3ZUv7WzwYVkUa2G/YL5rqB/aoscWT2rn/8VMnPdP7WhMxtqodvQIpACateAu\nNjoVaxpyKjePB1qE5EqA8BWeSHYsNvX7GYxl3Ex8uEy8J059wWSSZ63CK1+7x7LI\nMr/Tx5PLNplNvDOejGdyT7Yfti5oj0IwBdh3hhKJt9cnlubu5BedpoGE3hQz7VV2\nT1h60L73AgMBAAECggEAPVVDlh9uEPRXQ6MphUHf4Jrs308A37P/LXhwEjKUDxLf\n4DL88zvpeUpJJJV+VndBAQEBXIk/pbq5ZaoD7adNN2UOcQdZtK0+YZtRYu9o2mj8\nqtX4vYpCY1Ero8Upst1wmRx6hPYSBpnp9OqMOfGVaeKpzzDF644dsZlzeUbcpFjn\n58dW1FqFBr7iTQxYaF9xz5ZO04NhydDSfBOaOdrQKXGitRHX0CzHKEOkGLO+GSIp\ngMja0TMF4970BwTxLr4uJYp4BnbCXZ7XGcKBhQkdG2qNZE2kQFiKfBg4fmTCIwME\nmf9rg+cLUYSBJj+YmIguDXve8YnpwHRDmsLvEhjvDQKBgQDsEJnq//ymhVZwRPhP\nXWd6TS6F6EPWsYJVzFq3OVfSAh5IMU5IDZNVQNOraVl0dAFUAeSVA8F3tMJvBadC\nNzXwrenjr3UatBWSTpbcMFHYuvlorQ9O2BqdZsvbwSYz10ggcLU/aZTJXEup+4GF\nOfZNXCpxTkkGokpmOf6CXMoxqwKBgQDT8BEwE4JthRpj9+/VO+wfbWXWPXlFfAKd\nVXP/6D3Z02for5KWiGkrTnPGTYFyMMqDf4KHBmxrQh2PbDfKqOt+ZrCdeILRDVTn\nVJc8of1P6iMnUbfyHLKDyx5t0bk29/MjpsgpcJbNCc1NmwAUs/Ev3p7XNTiZwlQG\n8+S5s2fz5QKBgEvgVijT2RiJGSyC7rFL23vTHRYLfuqeKb98LNhhxRmKdsNLndbJ\nDkdDzAV3mjo1I0wmQ5umFmRspGZdEdLVvi+7Jsd5WRGZOqnJOvJRUa1xA8OihJ4a\nFgvrw7DB146oLtXGhGt6e0lxshxT6+CvrbxV2IqM2CoatgE/uM+cFZ17AoGATgvL\n6I5mq3omm8XEFhw4+eHJbLm6nPHr7JB5ZTXbAQou66ssKi8Vu5LqY45LKwf4q7Ab\nGyosZts0E4rgiMrn3eZnB7ZHRkDIkV+/Sd7Fb9ZjF6mqOYiD3LDCBeMDd9CbQve6\nIjiJ7/u6FOgNgZI6MUyj5dB9hXHgi6bpBdGhaFkCgYEA3CDZXEg7Hz7aDJnrsn+q\nyGbkyH03xIaZkW0OvOziVsxvPaT39mFUsPR9nfcqwhDFAVgbsOZMey2HtmvRiwCu\nWD8hHrcCgO7FQSjTJY+zdQMqZuzp5/Mi+CMIX08TBiDSDU0bq9+mLd4bf7HrSrRe\nL4t8okHAtCo6gvZFUq/gu18=\n-----END PRIVATE KEY-----\n",
                        "client_email": "fixitnow-service-new@fixitnow-698b4.iam.gserviceaccount.com",
                        "client_id": "101186740008532573154",
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/fixitnow-service-new%40fixitnow-698b4.iam.gserviceaccount.com",
                        "universe_domain": "googleapis.com"
        }
    def __init__(self):
        
        self.credentials = service_account.Credentials.from_service_account_info(
            self.SERVICE_ACCOUNT_JSON,
            scopes=['https://www.googleapis.com/auth/firebase.messaging']
        )

    def get_access_token(self):
        self.credentials.refresh(Request())
        return self.credentials.token

    def send_message(self, registration_tokens, notification_title, notification_body,image):
        results = []
        for token in registration_tokens:
            # Construct message payload
            message = {
                'message': {
                    'token': token,
                    'notification': {
                        'title': notification_title,
                        'body': notification_body,
                        'image':image
                    }
                }
            }

            # Prepare headers
            headers = {
                'Authorization': f'Bearer {self.get_access_token()}',
                'Content-Type': 'application/json'
            }

            # FCM v1 endpoint
            url = f'https://fcm.googleapis.com/v1/projects/{self.PROJECT_ID}/messages:send'

            # Send request
            response = requests.post(url, headers=headers, json=message)
            results.append(response.json())

        return results
class ComplaintView(viewsets.ModelViewSet):
    serializer_class = ComplaintSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = ComplaintFilter
    authentication_classes = [TokenAuthentication]
    parser_classes = (MultiPartParser, FormParser)
    
    def determine_media_type(self, file):
        if file is None:
            return None

        filename = file.name
        extension = filename.split('.')[-1].lower()

        if extension in ['jpg', 'jpeg', 'png', 'gif']:
            return 'image'
        elif extension in ['mp4', 'mov', 'avi', 'mkv']:
            return 'video'
        else:
            return 'unknown'

    def get_queryset(self):
        if self.action == 'user_complaints':
            return ComplaintModel.objects.filter(user=self.request.user).order_by("-id")
        elif self.action in ['like', 'dislike', 'update', 'partial_update', 'retrieve', 'destroy']:  # Include other actions
            return ComplaintModel.objects.all().order_by("-id")
        else:
            return ComplaintModel.objects.exclude(user=self.request.user).order_by("-id")

    def perform_create(self, serializer):
        media_type = self.determine_media_type(self.request.FILES.get('media'))
        serializer.save(user=self.request.user, media_type=media_type)

        try:
            
            tokens = list(
                UserInfoModel.objects.filter(location=serializer.data["location"])
                .exclude(user=self.request.user)
                .values_list("token", flat=True)
            )
            if tokens:
                fcm_sender = FCMv1Sender()
                fcm_sender.send_message(
                    tokens,
                    "New Complaint Issued in your city",
                    serializer.data["subject"],
                    serializer.data["media"] if media_type=="image" else "",
                )
        except Exception as e:
            print(f"Error sending FCM message: {e}")
            pass
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object() 
        if 'media' in request.FILES:
            media_type = self.determine_media_type(request.FILES.get('media'))
            instance.media = request.FILES.get('media')
            instance.media_type = media_type
            instance.status=True
            instance.approved_by=request.user
            instance.save()
            k=UserInfoModel.objects.get(user=self.request.user)
            k.score+=1
            k.save()
            try:
                tokens = list(
                    UserInfoModel.objects.filter(location=instance.location)
                    .exclude(user=self.request.user)
                    .values_list("token", flat=True)
                )
                if tokens:
                    fcm_sender = FCMv1Sender()
                    fcm_sender.send_message(
                        tokens,
                        "Issued resolved in your city",
                        instance.subject,
                        domain+instance.media.url if media_type=="image" else "",
                    )
            except Exception as e:
                print(f"Error sending FCM message: {e}")
                pass
            return Response({'message': 'Media updated successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'No media file provided'}, status=status.HTTP_400_BAD_REQUEST)
    # def update(self, request, *args, **kwargs):
    #     partial = kwargs.pop('partial', False)  # Allow partial updates
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance, data=request.data, partial=partial)
    #     media_type = self.determine_media_type(self.request.FILES.get('media'))
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save(approved_by=self.request.user, media_type=media_type, status=True)  # Update fields
    #     return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='like')
    def like(self, request, pk=None):
        complaint = self.get_object()
        user = request.user
        try:
            # Use likes_set and correct filter
            like = Like.objects.get(user=user, complaint=complaint)
            like.delete()  # Remove like
            return Response({'message': 'Like removed'}, status=status.HTTP_200_OK)
        except Like.DoesNotExist:
            Like.objects.create(user=user, complaint=complaint)  # Add like
            # Use dislikes_set and correct filter
            Dislike.objects.filter(user=user, complaint=complaint).delete()  # Remove dislike if exists
            return Response({'message': 'Liked'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='dislike')
    def dislike(self, request, pk=None):
        complaint = self.get_object()
        user = request.user
        try:
            # Use dislikes_set and correct filter
            dislike = Dislike.objects.get(user=user, complaint=complaint)
            dislike.delete()  # Remove dislike
            return Response({'message': 'Dislike removed'}, status=status.HTTP_200_OK)
        except Dislike.DoesNotExist:
            Dislike.objects.create(user=user, complaint=complaint)  # Add dislike
            # Use likes_set and correct filter
            Like.objects.filter(user=user, complaint=complaint).delete()  # Remove like if exists
            return Response({'message': 'Disliked'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='user-complaints')
    def user_complaints(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class UserInfoView(APIView):
    authentication_classes=[TokenAuthentication]
    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        user_info, created = UserInfoModel.objects.get_or_create(user=user)
        serializer = UserInfoSerializer(user_info, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK if not created else status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def get(self,request):
        user = request.user
        user_info, created = UserInfoModel.objects.get_or_create(user=user)
        serializer = UserInfoSerializer(user_info)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class CommentView(viewsets.ModelViewSet):
    serializer_class = CommentSerializer
    filter_backends = [DjangoFilterBackend]
    queryset = CommentModel.objects.order_by("-id")
    filterset_class = CommentFilter
    authentication_classes = [TokenAuthentication]
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)