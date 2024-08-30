from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import WebShellcode, LinuxShellcode, WindowsShellcode, CustomUser

@admin.register(WebShellcode)
class WebShellcodeAdmin(admin.ModelAdmin):
    list_display = ('title', 'file_type', 'uploaded_at')
    list_filter = ('file_type',)
    search_fields = ('title', 'content')

@admin.register(LinuxShellcode)
class LinuxShellcodeAdmin(admin.ModelAdmin):
    list_display = ('title', 'file_type', 'uploaded_at')
    list_filter = ('file_type',)
    search_fields = ('title', 'content')

@admin.register(WindowsShellcode)
class WindowsShellcodeAdmin(admin.ModelAdmin):
    list_display = ('title', 'file_type', 'uploaded_at')
    list_filter = ('file_type',)
    search_fields = ('title', 'content')

class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = CustomUser

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    model = CustomUser
    list_display = ('email', 'username', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active')
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'is_active', 'is_staff')
        }),
    )
    search_fields = ('email', 'username')
    ordering = ('email',)