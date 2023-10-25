from email.policy import default
from enum import unique
from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    description = models.TextField(blank=True)
    avatar = models.ImageField(upload_to="avatars", blank=True)
    isAuthenticated = models.BooleanField(default=False)

    # facultatif. Permet de personnaliser la représentation textuelle de l'objet dans l'interface d'administration. 
    # def __unicode__(self):
    #     return "{0}".format(self.code, )


# Serializer
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = "__all__"