# users/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterUserView,
    UserLoginView,
    UserProfileView,
    LogoutUserView,
    AlternativeLoginView
)

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', RegisterUserView.as_view(), name='user-register'),
    path('auth/login/', UserLoginView.as_view(), name='user-login'),
    path('auth/logout/', LogoutUserView.as_view(), name='user-logout'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # Alternative login using your existing serializer
    path('auth/login-alt/', AlternativeLoginView.as_view(), name='user-login-alt'),
    
    # User profile endpoints
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),
]