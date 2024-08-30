from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver


FILE_TYPE_CHOICES = [
    ('asm', 'ASM File'),
    ('c', 'C Source File'),
    ('python', 'Python Script'),
    ('txt', 'Text Document'),
]

class WebShellcode(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    file_type = models.CharField(max_length=10, choices=FILE_TYPE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis_result = models.TextField(null=True, blank=True) #####설명본 추가

    class Meta:
        db_table = 'web'

class LinuxShellcode(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    file_type = models.CharField(max_length=10, choices=FILE_TYPE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis_result = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'linux'

class WindowsShellcode(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    file_type = models.CharField(max_length=10, choices=FILE_TYPE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis_result = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'windows'


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_staff or self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_staff or self.is_superuser

# Elasticsearch 연동을 위한 신호 처리기
@receiver(post_save, sender=WebShellcode)
def update_web_document(sender, instance, **kwargs):
    from .documents import WebShellcodeDocument
    WebShellcodeDocument().update(instance)

@receiver(post_delete, sender=WebShellcode)
def delete_web_document(sender, instance, **kwargs):
    from .documents import WebShellcodeDocument
    WebShellcodeDocument().update(instance, action='delete')

@receiver(post_save, sender=LinuxShellcode)
def update_linux_document(sender, instance, **kwargs):
    from .documents import LinuxShellcodeDocument
    LinuxShellcodeDocument().update(instance)

@receiver(post_delete, sender=LinuxShellcode)
def delete_linux_document(sender, instance, **kwargs):
    from .documents import LinuxShellcodeDocument
    LinuxShellcodeDocument().update(instance, action='delete')

@receiver(post_save, sender=WindowsShellcode)
def update_windows_document(sender, instance, **kwargs):
    from .documents import WindowsShellcodeDocument
    WindowsShellcodeDocument().update(instance)

@receiver(post_delete, sender=WindowsShellcode)
def delete_windows_document(sender, instance, **kwargs):
    from .documents import WindowsShellcodeDocument
    WindowsShellcodeDocument().update(instance, action='delete')