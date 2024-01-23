from django.urls import path, include
from rest_framework import routers
from users.views import *
from .views import (
                    GetUsersView,
                    # CustomObtainAuthToken, # version token simple
                    CustomTokenObtainPairView, # version token JWT
                    UserLogout,
                    UserProfileView, 
                    UserUpdateView, 
                    CustomUserCreateView, 
                    CustomUserDeleteView, 
                    AvatarDeleteView,
                    PrevAvatarDeleteView,
                    ForgetPasswordView,
                    ResetPasswordView,
                    )
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

app_name = 'users'
router = routers.DefaultRouter()

urlpatterns = [
    path('', include(router.urls)),
    
    path('list/', GetUsersView.as_view(), name='list-users'),
    path('newUser/', CustomUserCreateView.as_view(), name='new-user'),
    
    # path('login/', CustomObtainAuthToken.as_view(), name='login'), # version Token simple
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'), # version Token JWT
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    path('logout/', UserLogout.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('updateProfile/<int:pk>/', UserUpdateView.as_view(), name='update-profile'),
    path('deleteUser/<int:pk>/', CustomUserDeleteView.as_view(), name='delete-user'),
    path('deleteAvatar/<int:pk>/', AvatarDeleteView.as_view(), name='delete-avatar'),
    path('deletePreviousAvatar/', PrevAvatarDeleteView.as_view(), name='delete-prev-avatar'),
    path('forgetPassword/', ForgetPasswordView.as_view(), name='forgetPassword-user'),
    path('reset-password/<str:uid>/<str:token>/', ResetPasswordView.as_view(), name='reset-password')
]

# for route in router.registry:
#     print(f"Registry for '{route}'")

# for route in router.urls:
#     print(f"URL for '{route}'")

# Routes
# GET /customUsers/ : Pour obtenir la liste des objets.
# POST /customUsers/ : Pour créer un nouvel objet.
# GET /customUsers/{pk}/ : Pour obtenir un objet spécifique.
# PUT /customUsers/{pk}/ : Pour mettre à jour un objet spécifique.
# DELETE /customUsers/{pk}/ : Pour supprimer un objet spécifique.

# Coté client
# Pour créer un nouvel utilisateur (inscription) : POST /users/customUsers/
# Pour récupérer la liste de tous les utilisateurs : GET /users/customUsers/
# Pour récupérer un utilisateur spécifique : GET /users/customUsers/{id}/
# Pour mettre à jour un utilisateur spécifique : PUT /users/customUsers/{id}/ ou PATCH /users/customUsers/{id}/
# Pour supprimer un utilisateur spécifique : DELETE /users/customUsers/{id}/