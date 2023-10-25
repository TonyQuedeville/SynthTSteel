from django.urls import path
from . import views
from users.views import *

app_name = 'users'

urlpatterns = [
    path('register/', views.register_api, name='register'),
    path('upload_avatar/', views.avatarUploadView, name='upload_avatar'),
    path('login/', views.login_api, name='login'),
    path('logout/', views.LogoutUserView, name='logout'),
    path('verifcookie/', views.VerifCookieUserView, name='verifcookie'),
    path('profile/', views.profile, name='profile'),
]
