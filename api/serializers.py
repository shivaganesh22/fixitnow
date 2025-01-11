from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
from django.utils import timezone
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
    lock = serializers.SerializerMethodField()
    approved_by = serializers.SerializerMethodField()
    likes_count = serializers.SerializerMethodField()
    dislikes_count = serializers.SerializerMethodField()
    user_liked = serializers.SerializerMethodField()
    user_disliked = serializers.SerializerMethodField()
    
    approve_likes_count = serializers.SerializerMethodField()
    approve_dislikes_count = serializers.SerializerMethodField()
    approve_user_liked = serializers.SerializerMethodField()
    approve_user_disliked = serializers.SerializerMethodField()

    class Meta:
        model = ComplaintModel
        fields = '__all__'
    def validate(self, attrs):
        if  ComplaintModel.objects.filter(subject__icontains=attrs["subject"],location__icontains=attrs["location"]).exists() or ComplaintModel.objects.filter(complaint__icontains=attrs["complaint"],location__icontains=attrs["location"]).exists():
            raise serializers.ValidationError({"subject": "Complaint Already exists"})
        return attrs
    def to_representation(self, instance):
        data = super().to_representation(instance)
        completed=False
        pending=True
        process=False
        showUpload=True
        showLock=True
        request = self.context.get('request') 
        if instance.approved_by is not None: 
            if timezone.now() > instance.approved_date and instance.approve_liked_set.count() > instance.approve_disliked_set.count(): 
                completed = True
            if timezone.now() < instance.approved_date:
                process=True
            if completed or process:
                pending=False
        if instance.lock is not None:
            if (timezone.now()<instance.lock_date or process) and not(instance.approved_by is not None and instance.approved_date<timezone.now()) :
                showLock=False
            if (timezone.now()<instance.lock_date and not request.user==instance.lock) and not(instance.approved_by is not None and instance.approved_date<timezone.now()):
                showUpload=False
        if not pending:
            showUpload=False
            showLock=False
        data["completed"]=completed
        data["pending"]=pending
        data["process"]=process
        data["showUpload"]=showUpload
        data["showLock"]=showLock
        return data
    def get_user(self, obj):
        return UserSerializer(obj.user).data
    def get_lock(self, obj):
        return UserSerializer(obj.lock).data

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
    
    def get_approve_likes_count(self, obj):
        return obj.approve_liked_set.count()

    def get_approve_dislikes_count(self, obj):
        return obj.approve_disliked_set.count()

    def get_approve_user_liked(self, obj):
        user = self.context['request'].user
        return obj.approve_liked_set.filter(user=user).exists()

    def get_approve_user_disliked(self, obj):
        user = self.context['request'].user
        return obj.approve_disliked_set.filter(user=user).exists()

class UserInfoSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    score = serializers.SerializerMethodField()
    class Meta:
        model=UserInfoModel
        fields="__all__"
    def get_score(self, obj):
        count=0
        complaints=ComplaintModel.objects.filter(approved_by=obj.user,approved_date__lt=timezone.now())
        for complaint in complaints:
            if complaint.approve_liked_set.count() > complaint.approve_disliked_set.count():
                count += 1
        return count
class CommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model=CommentModel
        fields="__all__"