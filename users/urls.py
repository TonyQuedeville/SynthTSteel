from django.urls import path, include
from . import views
from rest_framework import routers, generics
from users.views import *
from .views import (CustomObtainAuthToken, 
                    UserLogout,
                    UserProfileView, 
                    UserUpdateView, 
                    CustomUserCreateView, 
                    CustomUserDeleteView, 
                    AvatarDeleteView,
                    PrevAvatarDeleteView
                    )

app_name = 'users'
router = routers.DefaultRouter()
router.register(r'customUsers', views.UsersModelViewSet) #, basename='customuser')

urlpatterns = [
    path('', include(router.urls)),
    path('newUser/', CustomUserCreateView.as_view(), name='new-user'),
    path('login/', CustomObtainAuthToken.as_view(), name='login'),
    path('logout/', UserLogout.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('updateProfile/<int:pk>/', UserUpdateView.as_view(), name='update-profile'),
    path('deleteUser/', CustomUserDeleteView.as_view(), name='delete-user'),
    path('deleteAvatar/<int:pk>/', AvatarDeleteView.as_view(), name='delete-avatar'),
    path('deletePreviousAvatar/', PrevAvatarDeleteView.as_view(), name='delete-prev-avatar'),
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