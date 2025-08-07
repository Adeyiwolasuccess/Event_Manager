from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser





class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 
                  'phone', 'password', 'confirm_password')
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def validate(self, attrs):
        """Ensure passwords match and validate email uniqueness."""
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        """Create a new user instance."""
        validated_data.pop('confirm_password')
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone=validated_data.get('phone', ''),
            password=validated_data['password']
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login 
    """
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        """Validate user credentials using direct user lookup."""
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError({"detail": "Email and password are required."})

        # Direct user authentication without using Django's authenticate()
        try:
            # Get user by email
            from .models import CustomUser
            user = CustomUser.objects.get(email=email)
            
            # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError({"detail": "User account is disabled."})
            
            # Verify password
            if not user.check_password(password):
                raise serializers.ValidationError({"detail": "Invalid email or password."})
            
            # Success - add user to validated data
            attrs['user'] = user
            return attrs
            
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError({"detail": "Invalid email or password."})
        except Exception as e:
            raise serializers.ValidationError({"detail": f"Authentication failed: {str(e)}"})


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile details
    """
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 
                  'full_name', 'phone', 'role', 'created_at', 'updated_at')
        read_only_fields = ('id', 'email', 'role', 'created_at')

    def get_full_name(self, obj):
        return obj.full_name

# Aliases for compatibility with different naming conventions
RegisterSerializer = UserRegistrationSerializer
UserSerializer = UserProfileSerializer