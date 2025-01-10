from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api.views import *
router = DefaultRouter()
router.register('complaints', ComplaintView,basename="complaints")
urlpatterns = [
    path('', include(router.urls)),

    path('userinfo/',UserInfoView.as_view()),
    path('password/change/',ChangePasswordView.as_view()),
    path('password/reset/',ForgotPasswordView.as_view()),
    path('signup/',SignupView.as_view()),
    path('login/',LoginView.as_view()),
]
