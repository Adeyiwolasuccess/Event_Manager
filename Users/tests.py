# Users/tests.py - Enhanced test with debugging

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

CustomUser = get_user_model()

class UserAuthTests(APITestCase):
    def setUp(self):
        """Set up test data"""
        self.register_url = reverse('user-register')
        self.login_url = reverse('user-login')
        self.profile_url = reverse('user-profile')
        self.logout_url = reverse('user-logout')
        
        # Test user data
        self.user_data = {
            'email': 'testuser@example.com',
            'username': 'testuser',
            'password': 'testpassword123',
            'confirm_password': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User'
        }
        
        # Create a user manually for login tests
        self.test_user = CustomUser.objects.create_user(
            email='testuser@example.com',
            username='testuser',
            password='testpassword123',
            first_name='Test',
            last_name='User'
        )

    def test_user_registration_success(self):
        """Test successful user registration"""
        # Use different email for registration test
        reg_data = self.user_data.copy()
        reg_data['email'] = 'newuser@example.com'
        reg_data['username'] = 'newuser'
        
        response = self.client.post(self.register_url, reg_data, format='json')
        
        # Debug print
        if response.status_code != 201:
            print(f"Registration failed with status: {response.status_code}")
            print(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_success(self):
        """Test successful user login with enhanced debugging"""
        login_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword123'
        }
        
        # Debug: Check if user exists and is active
        print(f"User exists: {CustomUser.objects.filter(email='testuser@example.com').exists()}")
        user = CustomUser.objects.get(email='testuser@example.com')
        print(f"User is active: {user.is_active}")
        print(f"User check_password: {user.check_password('testpassword123')}")
        
        response = self.client.post(self.login_url, login_data, format='json')
        
        # Debug print
        print(f"Login response status: {response.status_code}")
        print(f"Login response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_profile_authenticated_access(self):
        """Test accessing user profile with authentication"""
        # Get JWT token for the user
        refresh = RefreshToken.for_user(self.test_user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'testuser@example.com')

    def test_user_profile_unauthenticated_access(self):
        """Test accessing user profile without authentication"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_logout_success(self):
        """Test successful user logout"""
        # Get JWT tokens
        refresh = RefreshToken.for_user(self.test_user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        logout_data = {'refresh': refresh_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)