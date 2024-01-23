"""
    Tests d'unité : Pour tester des parties spécifiques de votre code, comme des fonctions ou des méthodes. (TestCase)
    Tests d'intégration : Vérifient comment différentes parties de votre application fonctionnent ensemble.
    Tests fonctionnels : Pour simuler le comportement de l'utilisateur et tester l'interface utilisateur. (Selenium)
    
    Exécution des tests : python3 manage.py test
"""
from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.hashers import check_password
from .models import CustomUser
# from .serializer import CustomConfidentialSerializer

class CustomUserCreateViewTest(APITestCase):
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword',
            'password2': 'testpassword'
        }
        self.invalid_email = {
            'username': 'testuser2',
            'email': 'testexample.com',  # Email invalide
            'password': 'testpassword',
            'password2': 'testpassword'
        }
        self.invalid_passwords = {
            'username': 'testuser3',
            'email': 'test@example.com',
            'password': 'testpassword',
            'password2': 'testpasswordinvalid'
        }
        self.initial_user_count = CustomUser.objects.count()  # Initialiser le nombre d'utilisateurs ici

    def test_custom_user_create_view(self):
        """
        Vérifier la création d'un utilisateur en BDD
        """
        response = self.client.post('/users/newUser/', self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Vérifier si l'utilisateur a bien été créé dans la base de données
        self.assertEqual(CustomUser.objects.count(), self.initial_user_count + 1)

        created_user = CustomUser.objects.get(username='testuser')
        self.assertIsNotNone(created_user)
        self.assertEqual(created_user.email, 'test@example.com')

        # Vérifier si le mot de passe a été correctement haché
        self.assertTrue(check_password('testpassword', created_user.password))

    def test_custom_user_invalid_email(self):
        """
        Vérifier que l'utilisateur n'a pas été créé avec un email invalides
        """
        # self.initial_user_count = CustomUser.objects.count()
        response = self.client.post('/users/newUser/', self.invalid_email, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(CustomUser.objects.count(), self.initial_user_count)

    def test_custom_user_invalid_passwords(self):
        """
        Vérifier que l'utilisateur n'a pas été créé avec 2 mots de passe différents
        """
        # self.initial_user_count = CustomUser.objects.count()
        print("initial_user_count:", self.initial_user_count)
        response = self.client.post('/users/newUser/', self.invalid_passwords, format='json')
        print("response:", response.content)
        print(status.HTTP_400_BAD_REQUEST, type(status.HTTP_400_BAD_REQUEST))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # self.assertEqual(CustomUser.objects.count(), self.initial_user_count)
