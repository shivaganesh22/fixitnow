from django.contrib import admin

# Register your models here.
from .models import *
admin.site.register(PasswordChange)
admin.site.register(Verification)
admin.site.register(ComplaintModel)
admin.site.register(UserInfoModel)
admin.site.register(Like)
admin.site.register(Dislike)