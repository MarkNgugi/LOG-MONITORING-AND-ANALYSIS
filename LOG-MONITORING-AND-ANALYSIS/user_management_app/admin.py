from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    model = User
    # The fields to be used in displaying the User model.
    # These can be customized to fit your needs.
    list_display = ('username', 'email', 'full_name', 'contact_number', 'role', 'is_active', 'is_staff')
    list_filter = ('is_staff', 'is_active', 'role')
    search_fields = ('username', 'email', 'full_name')
    ordering = ('email',)
    
    # The fields to be used when adding or editing a user
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal info', {'fields': ('full_name', 'contact_number', 'date_of_birth', 'profile_picture', 'security_question', 'security_answer')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'role', 'department')}),
        ('Important dates', {'fields': ('created_at',)}),  # Exclude 'updated_at'
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'full_name', 'contact_number', 'date_of_birth', 'profile_picture', 'security_question', 'security_answer', 'role', 'department', 'is_active', 'is_staff'),
        }),
    )
    filter_horizontal = ()

# Register the custom User model with the custom UserAdmin
admin.site.register(User, UserAdmin)
