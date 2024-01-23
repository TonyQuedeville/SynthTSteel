
import json, os

from .models import CustomUser
from .serializer import CustomUserSerializer, CustomConfidentialSerializer

from urllib.parse import urlparse

from django.http import JsonResponse
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate, logout, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.shortcuts import redirect

from rest_framework import status, generics, authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken, APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import api_view
from rest_framework.parsers import MultiPartParser, FormParser

# User Login Version Token simple
# class CustomObtainAuthToken(ObtainAuthToken):    
#     def post(self, request):        
#         request_data = json.loads(request.body.decode('utf-8'))
#         username = request_data['username']
#         password = request_data['password']
#         user = authenticate(request, username=username, password=password)        
#         token, created = Token.objects.get_or_create(user=user)

#         response = JsonResponse({
#             'success': True, 
#             'message': 'Authentication successful',
#             'user': {
#                 'id': user.id,
#                 'username': user.username, 
#                 'email': user.email,
#                 'description': user.description,
#                 'avatar': "http://127.0.0.1:8000" + user.avatar.url if user.avatar else None,
#                 'isAuthenticated': user.is_authenticated,
#                 "tokenKey": token.key
#             }
#         }, status=status.HTTP_200_OK)
#         return response

# User Login Version Token JWT
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Vue de connection utilisateur et d'obtenion du jeton d'accès.

    Args:
        TokenObtainPairView (classe):

    Methods:
        post: Méthode pour gérer les requêtes POST et retourner une réponse.
        
    Return:

    """
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_200_OK:
            # Si la demande est réussie, retourner uniquement le jeton d'accès
            access_token = response.data.get('access')
            data = {'access': access_token}
            return Response(data, status=status.HTTP_200_OK)
        
        return response  # Si la demande échoue, retournez la réponse d'origine

# Logout
class UserLogout(APIView):
    """
    Vue de déconnection utilisateur
    
    Args:
        APIView (class): 
    
    Return:
        Reponse: Validation de déconnection
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # Vous pouvez utiliser cette classe uniquement si l'utilisateur est authentifié
    
    def post(self, request):
        # Effacez le jeton d'authentification côté client
        response = Response({"message": "Vous êtes déconnecté. A bientôt !"}, status=status.HTTP_200_OK)
        response.delete_cookie("authToken")
        
        # Vous pouvez également déconnecter l'utilisateur s'il utilise des sessions
        logout(request)

        return response


# User GetProfile
class UserProfileView(generics.RetrieveAPIView):
    """
    Vue du profil utilisateur

    Args:
        generics (class): Classe générique de DRF
        
    return:
        Objet profil utilisateur
    """
    # Tuto : https://www.youtube.com/watch?v=UU2hGwqvvk4&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=11
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]
    # authentication_classes = [authentication.SessionAuthentication, authentication.TokenAuthentication]
    authentication_classes = [JWTAuthentication]
    
    def get_object(self):
        user = self.request.user
        user.isAuthenticated = user.is_authenticated
        return user


# User UpdateProfile
class UserUpdateView(generics.UpdateAPIView):
    """
    Vue de modification du profil utilisateur

    Args:
        generics (class): Classe générique de DRF
    
    return:
        Objet profil utilisateur modifié
    """
    # Tuto : https://www.youtube.com/watch?v=k208JYSPha8&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=13
    queryset = CustomUser.objects.all()
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
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
    """
    Vue de création du profil utilisateur en BDD

    Args:
        generics (class): Classe générique de DRF
    
    return:
        Reponse: Erreur en cas d'echec
    """
    # Tuto : https://www.youtube.com/watch?v=u_Lz1XuwuJk&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=12
    queryset = CustomUser.objects.all()
    serializer_class = CustomConfidentialSerializer
    
    def perform_create(self, serializer):
        username = serializer.validated_data['username']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        password2 = self.request.data.get('password2')
        
        if not username:
            print("username:", username)
            return Response({'error': 'Pseudo manquant !'}, status=status.HTTP_400_BAD_REQUEST)
        elif not email:
            print("email:", email)
            return Response({'error': 'Email manquant !'}, status=status.HTTP_400_BAD_REQUEST)
        elif password != password2:
            print("passwords:", password, password2)
            return Response({'error': 'Les mots de passe ne correspondent pas !'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            print("Ok !")
            # Hacher le mot de passe avant de le stocker
            hashed_password = make_password(password)
            serializer.validated_data['password'] = hashed_password
            serializer.save()

            if serializer.is_valid():
                serializer.save()

# Delete User
class CustomUserDeleteView(generics.DestroyAPIView):
    """
    Vue de suppression du profil utilisateur

    Args:
        generics (class): Classe générique de DRF
    
    return:
        Reponse: Validation de suppression du profil
    """
    # Tuto : https://www.youtube.com/watch?v=BiocfGlqSfA&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=15
    queryset = CustomUser.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({"success": True, "message": "Votre compte a été supprimé."}, status=status.HTTP_204_NO_CONTENT)


# Delete avatar
class AvatarDeleteView(generics.DestroyAPIView):
    """
    Vue de suppression de l'avatar du profil utilisateur

    Args:
        generics (class): Classe générique de DRF
    
    return:
        Reponse: Validation de suppression de l'avatar
    """
    # Tuto : https://www.youtube.com/watch?v=BiocfGlqSfA&list=PLJuTqSmOxhNuN1iyCCx3pvkImo7JZpHHc&index=15
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    authentication_classes = [JWTAuthentication]
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
    """
    Vue de suppression de l'avatar du profil utilisateur

    Args:
        generics (class): Classe générique de DRF
    
    return:
        Reponse: Validation de suppression de l'avatar
    """
    authentication_classes = [JWTAuthentication]
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
class GetUsersView(generics.ListAPIView):
    """
    Getter: Liste des utilisateurs

    Args:
        generics (class): Classe générique de DRF
    """
    queryset = CustomUser.objects.all()
    authentication_classes = [JWTAuthentication]
    serializer_class = CustomUserSerializer

# Mot de passe oublié
class ForgetPasswordView(APIView):
    """
    Vue pour mot de passe oublié

    Args:
        APIView (class): Classe API

    Returns:
        Reponse: Message de confirmation d'envoi email
    """
    queryset = CustomUser.objects.all()
    
    def post(self, request):
        print("ForgetPasswordView !")
        # Récupérez l'adresse e-mail de la requête POST
        email = request.data.get('email')
        print("email:", email)
        if email is None:
            return Response({'message': 'Veuillez entrer votre adresse mail.'})

        # Vérifiez si l'utilisateur avec cette adresse e-mail existe
        try:
            user = CustomUser.objects.get(email=email)
            print("user:", user)
        except User.DoesNotExist:
            # Si l'utilisateur n'existe pas, ne révélez pas d'informations
            return Response({'message': 'Un e-mail de réinitialisation de mot de passe a été envoyé.'})

        # Générez un token unique pour réinitialiser le mot de passe
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        print("uid:", uid)
        token = default_token_generator.make_token(user)
        print("token:", token)
        
        # Enregistrez le token dans le champ reset_password_token de l'utilisateur
        user.reset_password_token = token
        user.save()
        print("save user !", user)

        # Créez le lien pour réinitialiser le mot de passe
        reset_link = reverse('reset-password', args=[uid, token]) or ''
        print("reset_link:", reset_link)
        if reset_link == '':
            reset_url = 'http://localhost:3000/reset-password/' + uid + "/" + token + "/"
        else:
            reset_url = request.build_absolute_uri(reset_link)  
        print("reset_url:", reset_url)

        # Envoyez un e-mail à l'utilisateur avec le lien de réinitialisation
        subject = 'Réinitialisation de mot de passe'
        message = f'Cliquez sur le lien suivant pour réinitialiser votre mot de passe : {reset_url}'
        email = "tonyquedeville@gmail.com" # pour les tests

        try:
            send_mail(
                subject,
                message,
                # 'webmaster@votre-domaine.com',  # L'adresse d'envoi par défaut
                [email],  # Destinataire (adresse e-mail de l'utilisateur)
                fail_silently=False,
            )
        except Exception as e:
            return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail de réinitialisation.'})

        return Response({'message': 'Un e-mail de réinitialisation de mot de passe a été envoyé.'})

class ResetPasswordView(APIView):
    """
    Vue pour validation du mot de passe

    Args:
        APIView (class): Classe API

    Returns:
        Reponse: Message de confirmation d'envoi email
    """
    def get(self, request, uid, token):
        User = get_user_model()
        try:
            user_id = urlsafe_base64_decode(uid)
            user = User.objects.get(pk=user_id)

            if default_token_generator.check_token(user, token):
                # La réinitialisation du mot de passe est autorisée, redirigez vers le formulaire de réinitialisation
                return redirect(f"/reset-password/{uid}/{token}/reset/")
            else:
                # Le token n'est pas valide, renvoyez un message d'erreur
                return Response({'message': 'Le lien de réinitialisation de mot de passe n\'est pas valide.'}, status=status.HTTP_BAD_REQUEST)
        except (User.DoesNotExist, ValueError, OverflowError):
            return Response({'message': 'Le lien de réinitialisation de mot de passe n\'est pas valide.'}, status=status.HTTP_BAD_REQUEST)


# ------------------------ Debugage ------------------------------------
# import logging

# # Configurer le journal
# logger = logging.getLogger('django.server')

# # Dans votre vue, vous pouvez enregistrer les informations de requête
# def post(self, request):
#     # Récupérez les informations de requête
#     logger.info(f"Requête POST reçue sur {request.path}: {request.data}")

#     # Votre logique de traitement de la requête ici
#     return Response({'message': 'Réponse de votre vue.'})