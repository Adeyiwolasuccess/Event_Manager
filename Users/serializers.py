# Users/serializers.py - COMPLETE WORKING VERSION

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a new user.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True
    )

    class Meta:
        model = CustomUser
        fields = (
            'email', 'username', 'first_name', 'last_name',
            'phone', 'password', 'confirm_password'
        )
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def validate(self, attrs):
        """
        Ensure passwords match.
        """
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {"password": "Passwords do not match."}
            )
        
        # Validate password is not empty
        if not attrs['password'].strip():
            raise serializers.ValidationError(
                {"password": "Password cannot be empty."}
            )
        
        return attrs

    def create(self, validated_data):
        """
        Create a new user with PROPERLY hashed password.
        """
        # Remove confirm_password
        validated_data.pop('confirm_password')
        
        # Extract password
        password = validated_data.pop('password')
        
        # Create user WITHOUT password first
        user = CustomUser(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone=validated_data.get('phone', ''),
        )
        
        # Set password PROPERLY using Django's method
        user.set_password(password)
        
        # Save user
        user.save()
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for logging in a user.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        """
        Validate credentials using direct password check
        """
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError(
                {"detail": "Both email and password are required."}
            )

        try:
            # Get user by email
            user = CustomUser.objects.get(email=email)
            
            # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError(
                    {"detail": "This account is disabled."}
                )
            
            # Check password using Django's method
            if not user.check_password(password):
                raise serializers.ValidationError(
                    {"detail": "Invalid credentials."}
                )
            
            attrs['user'] = user
            return attrs
            
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError(
                {"detail": "Invalid credentials."}
            )


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for returning user profile details.
    """
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = (
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'phone', 'role', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'email', 'role', 'created_at')

    def get_full_name(self, obj):
        """
        Combine first and last name for display.
        """
        return obj.full_name


# Aliases for compatibility with your existing views
RegisterSerializer = UserRegistrationSerializer
UserSerializer = UserProfileSerializer