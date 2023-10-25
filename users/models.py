from email.policy import default
from enum import unique
from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True)
    avatar = models.ImageField(max_length=255, upload_to="avatars", blank=True)
    isAuthenticated = models.BooleanField(default=False)

# Attributs par defaut fournis par django:
# username : Le nom d'utilisateur.
# password : Le mot de passe (généralement stocké de manière sécurisée à l'aide du hachage).
# email : L'adresse e-mail de l'utilisateur.
# first_name : Le prénom de l'utilisateur.
# last_name : Le nom de famille de l'utilisateur.
# is_active : Un indicateur pour savoir si le compte de l'utilisateur est actif.
# is_staff : Un indicateur pour savoir si l'utilisateur est membre du personnel administratif.
# is_superuser : Un indicateur pour savoir si l'utilisateur a des privilèges de superutilisateur.
# date_joined : La date à laquelle l'utilisateur a rejoint le site.
# last_login : La date de la dernière connexion de l'utilisateur.