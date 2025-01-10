from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
class ForgotPasswordSerializer(serializers.Serializer):
    email=serializers.EmailField()
class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField(required=True)
    password=serializers.CharField(max_length=100)
class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    class Meta:
        model=User
        fields=['username','password','email',"first_name"]

    def validate(self, attrs):
        if len(attrs['password'])<8:
            raise serializers.ValidationError({"password": "Password must be greater or equal to 8 characters"})
        elif User.objects.filter(username=attrs['username'].title()).exists():
            raise serializers.ValidationError({"username": "User already exists with this username"})
        elif User.objects.filter(email=attrs['email'].lower()).exists():
            raise serializers.ValidationError({"email": "User already exists with this email"})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'].title(),
            email=validated_data['email'].lower(),
            first_name=validated_data["first_name"]
        )

        
        user.set_password(validated_data['password'])
        user.save()
        
        return user
class ComplaintSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    approved_by = serializers.SerializerMethodField()
    likes_count = serializers.SerializerMethodField()
    dislikes_count = serializers.SerializerMethodField()
    user_liked = serializers.SerializerMethodField()
    user_disliked = serializers.SerializerMethodField()

    class Meta:
        model = ComplaintModel
        fields = '__all__'
    def validate(self, attrs):
        if  ComplaintModel.objects.filter(subject__icontains=attrs["subject"],location__icontains=attrs["location"]).exists() or ComplaintModel.objects.filter(complaint__icontains=attrs["complaint"],location__icontains=attrs["location"]).exists():
            raise serializers.ValidationError({"subject": "Complaint Already exists"})
        return attrs

    def get_user(self, obj):
        return UserSerializer(obj.user).data

    def get_approved_by(self, obj):
        if obj.approved_by:
            return UserSerializer(obj.approved_by).data
        return None

    def get_likes_count(self, obj):
        return obj.liked_set.count()

    def get_dislikes_count(self, obj):
        return obj.disliked_set.count()

    def get_user_liked(self, obj):
        user = self.context['request'].user
        return obj.liked_set.filter(user=user).exists()

    def get_user_disliked(self, obj):
        user = self.context['request'].user
        return obj.disliked_set.filter(user=user).exists()

class UserInfoSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model=UserInfoModel
        fields="__all__"