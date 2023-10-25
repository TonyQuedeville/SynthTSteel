from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from users.models import CustomUser 
from django.db.models import Q
from django.contrib.auth import login, logout, authenticate
from rest_framework.authtoken.models import Token
from PIL import Image


@csrf_exempt
def login_api(request):  
    print("login_api !")      
    if request.method == 'POST':
        # Le cookie CSRF est automatiquement géré par Django via le formulaire
        try:
            # Récupérez le corps de la requête JSON
            request_data = json.loads(request.body.decode('utf-8'))
            # print("Received data:", request_data)

            # Récupérez les informations d'identification de l'utilisateur
            username = request_data['username']
            password = request_data['password']

            # Authentification de l'utilisateur
            user = authenticate(request, username=username, password=password)            
            
            # Supprimer le jeton existant de l'utilisateur s'il en a un
            if hasattr(user, 'auth_token'):
                user.auth_token.delete()
            # Créez un jeton d'authentification pour l'utilisateur
            token = Token.objects.create(user=user)
            print("token key:", token.key)

            avatar_url = ''
            if user.avatar:
                avatar_url = request.build_absolute_uri(user.avatar.url)
            

            if user is not None:
                login(request, user)
            
            if request.user.is_authenticated:
                user = request.user
                
                response = JsonResponse({
                    'success': True, 
                    'message': 'Authentication successful',
                    'user': {
                        'username': user.username, 
                        'email': user.email,
                        'description': user.description,
                        'avatar': avatar_url,
                        'isAuthenticated': True,
                        "tokenKey": token.key
                        }
                    })
                response["Access-Control-Allow-Origin"] = "http://localhost:3000"
                response["Access-Control-Allow-Credentials"] = "true"
                return response
        
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

@csrf_exempt
def LogoutUserView(request):
    if request.method == 'POST':
        try:            
            # Récupérez le token à partir de la requête
            token_key = request.META.get('HTTP_AUTHORIZATION', '').split('Token ')[-1]
            token = Token.objects.get(key=token_key)
            user = token.user
            print(user)

            # supprime le token
            if token:
                token.delete() 

            logout(request)@csrf_exempt
            return JsonResponse({'success': True, 'message': 'Logged out'})
        
        except Token.DoesNotExist:
            print('Invalid token !')
            return JsonResponse({'message': 'Invalid token'}, status=400)



@csrf_exempt
def register_api(request):
    if request.method == 'POST':
        try:
            # Récupérez le corps de la requête JSON
            request_data = json.loads(request.body.decode('utf-8'))
            # print("Received data:", request_data)
            
            # Vérifiez si l'utilisateur existe déjà
            existing_user = CustomUser.objects.filter(
                Q(username=request_data['username']) | Q(email=request_data['email'])
            ).first()
            if existing_user:
                return JsonResponse({
                    'success': False,
                    'message': 'User with this username already exists.'
                })

            # Créez un nouvel utilisateur en utilisant les données reçues
            new_user = CustomUser.objects.create_user(
                username=request_data['username'],
                email=request_data['email'],
                password=request_data['password'],
            )

            # Enregistrez l'utilisateur dans la base de données
            new_user.save()
            login(request, new_user)
            
            # Créez un jeton d'authentification pour le nouvel utilisateur
            token, created = Token.objects.get_or_create(user=new_user)
            
            return JsonResponse({
                'success': True, 
                'message': 'User registration successful',
                'user': {
                    'username': request_data['username'],
                    'email': request_data['email'],
                    'is_authenticated': True,
                    'token': token.key  
                }
                })
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


@csrf_exempt
def profile(request):
    if request.method == 'POST':
        try:
            # Récupérez le corps de la requête JSON
            request_data = json.loads(request.body.decode('utf-8'))
            
            # Récupérez le token à partir de la requête
            token_key = request.META.get('HTTP_AUTHORIZATION', '').split('Token ')[-1]

            # Trouvez le token dans la base de données
            try:
                token = Token.objects.get(key=token_key)
            except Token.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid token'})

            # Utilisez le token pour obtenir l'utilisateur
            user = token.user
            
            # # Mettez à jour l'utilisateur 
            user.description = request_data['description']
            user.avatar = 'avatars/' + request_data['avatar']
            user.save()
            
            return JsonResponse({
                'success': True, 
                'message': 'User update successful',
                })
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

@csrf_exempt
def avatarUploadView(request):
    print("AvatarUploadView !")
    if request.method == 'POST':
        try:            
            # Récupérez le token à partir de la requête
            token_key = request.META.get('HTTP_AUTHORIZATION', '').split('Token ')[-1]

            # Token dans la base de données
            try:
                token = Token.objects.get(key=token_key)
            except Token.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid token'})

            user = token.user            
            if user:
                # Récupérez le fichier d'avatar à partir de la requête
                avatar_file = request.FILES.get('avatar')

                if not avatar_file:
                    return JsonResponse({'message': 'No avatar file provided'}, status=400)

                # Vérifiez le type du fichier (image)
                if not avatar_file.content_type.startswith('image'):
                    return JsonResponse({'message': 'Invalid file type'}, status=400)

                # Créez une instance d'image avec Pillow
                image = Image.open(avatar_file)
                image = image.convert('RGB')  # Assurez-vous que l'image est en mode RGB

                # Redimensionnez l'image si nécessaire
                # image = image.resize((100, 100), Image.ANTIALIAS)

                # Enregistrez l'image dans le dossier d'avatars
                user.avatar.save(avatar_file.name, avatar_file)
                
                return JsonResponse({'message': 'Avatar uploaded successfully'})
        
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})    

@csrf_exempt
def VerifCookieUserView(request):
    print("VerifCookieUserView !")
    if request.method == 'POST':
        try:            
            # Récupérez le token à partir de la requête
            token_key = request.META.get('HTTP_AUTHORIZATION', '').split('Token ')[-1]

            # Token dans la base de données
            try:
                # token = request.COOKIES.get('sessionid', '')
                token = Token.objects.get(key=token_key)
                print("token:", token)
            except Token.DoesNotExist:
                print('Invalid token !')
                return JsonResponse({'success': False, 'message': 'Invalid token'})

            user = token.user 
            if user.is_authenticated:
                return JsonResponse({
                    'success': True, 
                    'message': 'Authentication successful',
                    'user': {
                        'username': user.username, 
                        'email': user.email,
                        'description': user.description,
                        'avatar': user.avatar.url,
                        'is_authenticated': True,
                        "tokenKey": token.key
                        }
                })
                
        except json.JSONDecodeError:
            print('no token !')
            return JsonResponse({'success': False, 'message': 'no token'})
    else:
        print('Invalid request method !')
        return JsonResponse({'success': False, 'message': 'Invalid request method'})
