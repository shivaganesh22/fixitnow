from django.shortcuts import render
from django.contrib import messages
from api.models import *
from django.utils import timezone
from datetime import timedelta
def password_reset(r):
    msg=""
    try:
        obj=PasswordChange.objects.get(token=r.GET['token'])
        now = timezone.now()
        if now - obj.date_added > timedelta(minutes=10):
            msg="Link Expired"
    except:
        msg="Invalid Link"
    if r.method=="POST":
        password1=r.POST["password1"]
        password2=r.POST["password2"]
        if password1!=password2:
            messages.error(r,"Password doesnot match")
        elif len(password1)<8:
            messages.error(r,"Password should be 8 characters")
        else:
            obj.user.set_password(password1)
            obj.user.save()
            obj.delete()
            msg="Password Changed Successfully"

    return render(r,'password.html',{"msg":msg})
def home(r):
    return render(r,'index.html')
def verification_view(r):
    msg=""
    try:
        obj=Verification.objects.get(token=r.GET['token'])
        if obj.is_verified:
            msg="Already Verified"
        else:
            obj.is_verified=True
            obj.save()
            msg="Email Verified Successfully"
    except:
        msg="Invalid Link"
    return render(r,'verification.html',{"msg":msg})