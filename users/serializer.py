from .models import CustomUser
from rest_framework import serializers

# Serializer
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'password', 'description', 'avatar', 'isAuthenticated')
        read_only_fields = ('id',)  # Le champ id est en lecture seule
        extra_kwargs = {'avatar': {'required': False},
                        'description': {'required': False},
                        'password': {'required': False}} # avatar et description facultatif
