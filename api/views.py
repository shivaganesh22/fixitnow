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
from django.utils import timezone
import uuid
from django.core.mail import send_mail
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
import requests
from google.auth.transport.requests import Request
from google.oauth2 import service_account
# domain="http://192.168.50.208:8000"
domain="https://fixitnow.pythonanywhere.com"
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
    SERVICE_ACCOUNT_JSON ={
  "type": "service_account",
  "project_id": "fixitnow-698b4",
  "private_key_id": "0af0fed30b42c64ddf92accbde00b3436d5c39f1",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDI123ScJWao1dm\nZX//rNhlpbq8/UZXkK4WihvdHn4MfFgXNz7OwFsJ9+8ktQLzEiwapt8tMcS5IYB4\nckwd4d7+H6n8OG1V3wH36lptSwv9VJZVU7bQnhIoqJzDNoTni63zZDAc+hTdHylu\n4G4KFXc3ci4MuGWgneyufnJ2CFUtRMwL+T38rn2jcbInv3uUbdy609adqH3DkomA\nzcxHU4bUETE5BJdyY/FkIUvHdG9LkwDQILkZ2Rq6yuDP6yY/wTAClQQJdQr3KHxr\nQESdFRjlcAamoPCPjvQr9ay6bdCK4OuRUxUrTzrH9F0FiS9Vqe61Xs8d+kZxkltz\nfon6wKjJAgMBAAECggEAFSwWrPZG4yIggtAk5fJV7qNBtA4cJft/yqr9BHqkLZNH\nIw1lHt0Ky9p5+JvnZ3HtOdMJGGXUd/K27RuZeBX5UL9MR2U4a3LCrZykMzzT0v0h\nivW0AjqDrgsWWYLsEE+6gvu3EbrwS54vGzvoBcKdCniML7WZqwyy6HM2hEhdGFQm\nC6pjV3PMzMr8zGJVrxZYXBW4TI3qL+UuSumifqfqKOYwX60URDdJTJfyxNLLsGpI\ndXQcI3IiQv8ev0kdihndHhbRQWpIEifH13Akgra0CzKWvdPsinDQTrq7v1JH+T1J\nlH17iQ/YDfi3yv34htOAkzG/9xKz0HNwaQs3l/SoAQKBgQD5UWEMl7L8Ji2FfbM8\n8ENk0MEFXXKr1Qcc/DiAeHuNGpIeJKqF/RKm1pN5uQa6AKDdJDt0SiVstTuBo60R\ndQ+CkLfYilIuyr9XVaEMjDLgQo+NVfbH00kZQM9ZcD5z9PV5lNJkQPjntjBiU1at\nIBs/0HU+wgNZ7aunudfOoss8AQKBgQDOOXGSmn473qv9CRZsQhmlzLR0B7jYTY6h\npCphAGqnM7LGH1S5p/NUbrJtGcYqfPrL1ZkLWzhpEVtk0742d1y2eoJiCpuX4AwG\n8Rr5OhbuUWOhYiE18OxjIQ/7fLnqd2VL2NXg2lpI9dp65ZBD1eZzSOkKCxsChRiX\nfYaU/F6MyQKBgQC7w/MwNauBxQrxhzqPAW/wJFvKO5eaG8TQqo+vCY4bNdCnzPt0\nD6WVavMEcDnFqaV9BsWUDidjWJZpSyiThjLZJT6gYYQFY4J5Nq8ksQ274cUVL5G8\n6r4Zu7qtZCBU2j5pg5B0Go6ai5ai5prXpd9/zvIOArXda2ak2gzSvb4MAQKBgGdi\nZux/JR+wjvpojuQw8xiqmiC9Kk7N+t5QJarBgbZW9Z3bYSc96n/+italIDJ2u2hq\nqbIGxi3uNKpEeMxnZIRawHiUJtKp0H2+a65cD9jj1pW2Uz3ujSNZFOEX80B3IMI4\nb2itLqv7DM+lvIA1gLV07NdLH/xQazavCEQyjNf5AoGBAIzjOI8v2B5AH5P2UVLq\ntnli4+M18v1/pxMOzoSKUhCPfwF2Mojr93vQEEepHVM7rW2XHSpYWCk9XT+/TIKB\n2U3B4+Zl3uff/o7xYxddmhjU+YNKenjL5aYPkkwFHF662nEnwnUxZWmKuWUeKdP0\nmRTRFFc3Wq6BPXtk9BU5/KaT\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-4k75o@fixitnow-698b4.iam.gserviceaccount.com",
  "client_id": "114736655823775041520",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-4k75o%40fixitnow-698b4.iam.gserviceaccount.com",
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
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request 
        return context
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
        elif self.action in ['like', 'lock','dislike','approve_like','approve_dislike', 'update', 'partial_update', 'retrieve', 'destroy']:  # Include other actions
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
        if 'approved_media' in request.FILES:
            media_type = self.determine_media_type(request.FILES.get('approved_media'))
            instance.approved_media = request.FILES.get('approved_media')
            instance.approved_media_type = media_type
            instance.status=True
            instance.approved_by=request.user
            instance.lock=None
            ApproveLike.objects.filter(complaint=instance).delete()
            ApproveDislike.objects.filter(complaint=instance).delete()
            instance.approved_date=timezone.now() + timedelta(days=1)
            instance.save()

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
                        "Issue Updated in your city",
                        instance.subject,
                        domain+instance.approved_media.url if media_type=="image" else "",
                    )
            except Exception as e:
                print(f"Error sending FCM message: {e}")
                pass
            return Response({'message': 'Media updated successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'No media file provided'}, status=status.HTTP_400_BAD_REQUEST)

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
    @action(detail=True, methods=['get'], url_path='approve_like')
    def approve_like(self, request, pk=None):
        complaint = self.get_object()
        user = request.user
        try:
            like = ApproveLike.objects.get(user=user, complaint=complaint)
            like.delete()  # Remove like
            return Response({'message': 'Like removed'}, status=status.HTTP_200_OK)
        except ApproveLike.DoesNotExist:
            ApproveLike.objects.create(user=user, complaint=complaint)  # Add like
            # Use dislikes_set and correct filter
            ApproveDislike.objects.filter(user=user, complaint=complaint).delete()  # Remove dislike if exists
            return Response({'message': 'Liked'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='approve_dislike')
    def approve_dislike(self, request, pk=None):
        complaint = self.get_object()
        user = request.user
        try:
            # Use dislikes_set and correct filter
            dislike = ApproveDislike.objects.get(user=user, complaint=complaint)
            dislike.delete()  # Remove dislike
            return Response({'message': 'Dislike removed'}, status=status.HTTP_200_OK)
        except ApproveDislike.DoesNotExist:
            ApproveDislike.objects.create(user=user, complaint=complaint)  # Add dislike
            # Use likes_set and correct filter
            ApproveLike.objects.filter(user=user, complaint=complaint).delete()  # Remove like if exists
            return Response({'message': 'Disliked'}, status=status.HTTP_200_OK)
    @action(detail=True, methods=['get'], url_path='lock')
    def lock(self, request, pk=None):
        complaint = self.get_object()
        user = request.user
        complaint.lock=user
        complaint.approved_by=None
        complaint.lock_date=timezone.now()+timedelta(days=4)
        complaint.save()
        return Response({'message': 'Complaint locked successfully'}) 

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
