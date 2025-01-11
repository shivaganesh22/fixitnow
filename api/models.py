from django.db import models,IntegrityError
from django.contrib.auth.models import User
from django.db.models import UniqueConstraint
# Create your models here.
class PasswordChange(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    token=models.CharField(max_length=100)
    date_added = models.DateTimeField(auto_now_add=True)
    def __str__(self) :
        return str(self.user)+ "  "+self.token
class Verification(models.Model):
    token=models.CharField(max_length=100)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    is_verified=models.BooleanField(default=False)
    def __str__(self):
        return self.user.username+" "+self.token

class ComplaintModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="created_by")
    subject=models.TextField()
    complaint = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=False)
    lock = models.ForeignKey(User,on_delete=models.CASCADE,related_name="locked_user",blank=True,null=True)
    lock_date =models.DateTimeField(blank=True,null=True)
    location=models.TextField()
    media = models.FileField(upload_to='uploads/', blank=True, null=True)
    media_type = models.CharField(max_length=10, blank=True, null=True) 
    approved_by=models.ForeignKey(User,on_delete=models.CASCADE,related_name="approved_by",null=True,blank=True)
    approved_media=models.FileField(upload_to='uploads/', blank=True, null=True)
    approved_media_type = models.CharField(max_length=10, blank=True, null=True) 
    approved_date=models.DateTimeField(blank=True,null=True)
    # class Meta:
    #     unique_together = ('subject', 'location')

class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="liked_user")
    complaint = models.ForeignKey(ComplaintModel, on_delete=models.CASCADE, related_name='liked_set')
    class Meta:
        unique_together = ('user', 'complaint')  

class Dislike(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="disliked_user")
    complaint = models.ForeignKey(ComplaintModel, on_delete=models.CASCADE, related_name='disliked_set')
    class Meta:
        unique_together = ('user', 'complaint')    
class ApproveLike(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="approve_liked_user")
    complaint = models.ForeignKey(ComplaintModel, on_delete=models.CASCADE, related_name='approve_liked_set')
    class Meta:
        unique_together = ('user', 'complaint')  

class ApproveDislike(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="approve_disliked_user")
    complaint = models.ForeignKey(ComplaintModel, on_delete=models.CASCADE, related_name='approve_disliked_set')
    class Meta:
        unique_together = ('user', 'complaint')    
class UserInfoModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token=models.TextField()
    location=models.TextField()
class CommentModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    complaint = models.ForeignKey(ComplaintModel, on_delete=models.CASCADE, related_name='commented')
    comment=models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.user.username