
import json, os
from os.path import join
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import authenticate, logout
from django.contrib.auth.hashers import make_password
from urllib.parse import urlparse
from .serializer import CustomUserSerializer
from .models import CustomUser
from rest_framework import viewsets, status, permissions, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken, APIView
from rest_framework.decorators import api_view
from rest_framework.parsers import MultiPartParser, FormParser

# User Login
class CustomObtainAuthToken(ObtainAuthToken):    
    def post(self, request):        
        request_data = json.loads(request.body.decode('utf-8'))
        username = request_data['username']
        password = request_data['password']
        user = authenticate(request, username=username, password=password)        
        token, created = Token.objects.get_or_create(user=user)
        
        response = JsonResponse({
            'success': True, 
            'message': 'Authentication successful',
            'user': {
                'id': user.id,
                'username': user.username, 
                'email': user.email,
                'description': user.description,
                'avatar': "http://127.0.0.1:8000" + user.avatar.url if user.avatar else None,
                'isAuthenticated': user.is_authenticated,
                "tokenKey": token.key
            }
        }, status=status.HTTP_200_OK)
        return response

# Logout
class UserLogout(APIView):
    permission_classes = [IsAuthenticated]  # Vous pouvez utiliser cette classe uniquement si l'utilisateur est authentifié

    def post(self, request):
        print("logout !")

        # Vous pouvez également déconnecter l'utilisateur si vous utilisez des sessions en appelant :
        logout(request)

        # Effacez les cookies de session si vous en utilisez.
        if request.session:
            request.session.flush()

        return Response({"message": "Vous êtes déconnecté."}, status=status.HTTP_200_OK)


# User GetProfile
class UserProfileView(generics.RetrieveAPIView):
    # Tuto : https://www.youtube.com/watch?v=UU2hGwqvvk4&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=11
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user = self.request.user
        user.isAuthenticated = user.is_authenticated
        return user


# User UpdateProfile
    # Tuto : https://www.youtube.com/watch?v=k208JYSPha8&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=13
class UserUpdateView(generics.UpdateAPIView):
    queryset = CustomUser.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = CustomUserSerializer
    lookup_field = 'pk'
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, *args, **kwargs):
        # Récupérez l'ID de l'objet à mettre à jour à partir des paramètres d'URL
        pk = kwargs.get('pk')       

        # Utilisez le serializer pour effectuer la mise à jour de l'objet
        instance = self.get_object()
        
        # Récupérez les données de la requête
        content_type = request.content_type
        if content_type == 'application/json':
            data = json.loads(request.body.decode('utf-8'))
        else:
            data = request.data

        # Vérifiez si le champ 'avatar' est vide (c'est-à-dire "")
        if 'avatar' in data and data['avatar'] == "":
            # Ne mettez pas à jour l'avatar
            data.pop('avatar')
        
        serializer = self.get_serializer(instance, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)


# New User
class CustomUserCreateView(generics.CreateAPIView):
    # Tuto : https://www.youtube.com/watch?v=u_Lz1XuwuJk&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=12
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    
    def perform_create(self, serializer):
        # Hacher le mot de passe avant de le stocker
        password = serializer.validated_data['password']
        data = self.request.data
        password2 = data.get('password2')
        
        if password and password == password2:
            hashed_password = make_password(password)
            serializer.validated_data['password'] = hashed_password
            serializer.save()

# Delete User
class CustomUserDeleteView(generics.DestroyAPIView):
    # Tuto : https://www.youtube.com/watch?v=BiocfGlqSfA&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=15
    queryset = CustomUser.objects.all()
    
    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({"success": True, "message": "Votre compte a été supprimé."}, status=status.HTTP_204_NO_CONTENT)


# Delete avatar
class AvatarDeleteView(generics.DestroyAPIView):
    # Tuto : https://www.youtube.com/watch?v=BiocfGlqSfA&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=15
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        user = self.request.user

        # Obtenez l'utilisateur actuel à partir de la requête
        try:
            user = CustomUser.objects.get(pk=user.pk)
        except CustomUser.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Supprimez l'avatar de l'utilisateur
        print("user.avatar:", user.avatar)
        if user.avatar:
            user.avatar.delete()  # Supprimez le fichier physique de l'avatar

        # Réinitialisez le champ "avatar" de l'utilisateur
        user.avatar = None
        user.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


# Delete previous avatar
class PrevAvatarDeleteView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        # Récupérez l'utilisateur actuel à partir de la requête
        data = request.data
        avatar_url = data.get('avatarUrl')
        
        if avatar_url is not None:
            # Extrait le nom du fichier de l'URL de l'avatar
            parsed_url = urlparse(avatar_url)
            try:
                filename = parsed_url.path.split('/')[-2] + "/" + parsed_url.path.split('/')[-1]
            except:
                return Response(status=status.HTTP_204_NO_CONTENT)
            
            # Joindre le nom du fichier avec le répertoire MEDIA_ROOT
            avatar_path = os.path.join(settings.MEDIA_ROOT, filename)

            if os.path.exists(avatar_path):
                os.remove(avatar_path)
                return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Utilisé pour la liste des utilisateurs
class UsersModelViewSet(viewsets.ModelViewSet):
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = CustomUser.objects.all()
    
    # CRUD CustomUser
    # @action(detail=False, methods=['post'])
    # def custom_list(self, request):
    #     # Logique pour obtenir la liste des profils d'utilisateurs (GetUsers)
    #     queryset = CustomUser.objects.all()
    #     serializer = CustomUserSerializer(queryset, many=True)
    #     return Response(serializer.data)

    # @action(detail=True, methods=['post'])
    # def custom_create(self, request):
    #     # Logique pour créer un nouveau profil d'utilisateur (Register, CreateUser)
    #     queryset = CustomUser.objects.create()
    #     serializer = CustomUserSerializer(queryset, many=True)
    #     return Response(serializer.data)
        
    # @action(detail=True, methods=['get']) #, url_path ='login')
    # def custom_retrieve(self, request, pk=None):
    #     print("custom_retrieve:", pk)
    #     # Logique pour obtenir un profil d'utilisateur spécifique (GetUserByXxx)
    #     if pk == 'update':
    #         # Récupération de l'utilisateur actuellement connecté
    #         if request.user.is_authenticated:
    #             user = request.user
    #             serializer = CustomUserSerializer(user)
    #             return Response(serializer.data)
    #         else:
    #             return Response({'detail': 'User is not authenticated.'}, status=status.HTTP_401_UNAUTHORIZED)
            
        # elif pk == 'login':
        #     # Récupération de l'utilisateur par nom d'utilisateur et mot de passe
        #     username = request.data.get('username')
        #     password = request.data.get('password')            
        #     user = CustomUser.objects.get(username=username)
            
        #     if user.check_password(password):
        #         serializer = CustomUserSerializer(user)
        #         return Response(serializer.data)
        #     else:
        #         return Response({'detail': 'Identifiants incorrects'}, status=status.HTTP_400_BAD_REQUEST)
            
        # else:
        #     # Récupération par ID
        #     try:
        #         user = CustomUser.objects.get(id=pk)
        #         serializer = CustomUserSerializer(user)
        #         return Response(serializer.data)
        #     except CustomUser.DoesNotExist:
        #         return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    # def custom_update(self, request, pk=None):
    #     # Logique pour mettre à jour un profil d'utilisateur (UpdateUser)
    #     ...

    # def custom_destroy(self, request, pk=None):
    #     # Logique pour supprimer un profil d'utilisateur (DeleteUser)
    #     ...
    
# @csrf_exempt
# def loginView(request):  
#     print("login !")      
#     if request.method == 'POST':
#         # Le cookie CSRF est automatiquement géré par Django via le formulaire
#         try:
#             # Récupérez le corps de la requête JSON
#             request_data = json.loads(request.body.decode('utf-8'))
#             # print("Received data:", request_data)

#             # Récupérez les informations d'identification de l'utilisateur
#             username = request_data['username']
#             password = request_data['password']

#             # Authentification de l'utilisateur
#             user = authenticate(request, username=username, password=password)            
            
#             # Supprimer le jeton existant de l'utilisateur s'il en a un
#             if hasattr(user, 'auth_token'):
#                 user.auth_token.delete()
#             # Créez un jeton d'authentification pour l'utilisateur
#             token = Token.objects.create(user=user)
#             print("token key:", token.key)

#             avatar_url = ''
#             if user.avatar:
#                 avatar_url = request.build_absolute_uri(user.avatar.url)
            

#             if user is not None:
#                 login(request, user)
            
#             if request.user.is_authenticated:
#                 user = request.user
                
#                 response = JsonResponse({
#                     'success': True, 
#                     'message': 'Authentication successful',
#                     'user': {
#                         'username': user.username, 
#                         'email': user.email,
#                         'description': user.description,
#                         'avatar': avatar_url,
#                         'isAuthenticated': True,
#                         "tokenKey": token.key
#                         }
#                     })
#                 response["Access-Control-Allow-Origin"] = "http://localhost:3000"
#                 response["Access-Control-Allow-Credentials"] = "true"
#                 return response
        
#         except json.JSONDecodeError:
#             return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
#     else:
#         return JsonResponse({'success': False, 'message': 'Invalid request method'})