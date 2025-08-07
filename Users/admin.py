from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin # Custom User Admin
from .models import CustomUser

# Register your models here.
@admin.register(CustomUser)
class UserAdmin(BaseUserAdmin):
    """
    Custom User Admin to manage CustomUser model
    """
    list_display = ('email', 'username', 'first_name', 'last_name', 'role', 'is_active', 'created_at' )
    list_filter = ('role', 'is_active', 'is_staff', 'created_at')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('-created_at',)

    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('phone', 'role', 'created_at', 'updated_at')
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 
                      'phone', 'role', 'password1', 'password2'),
        }),
    )