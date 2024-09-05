from django.contrib import admin
from .models import UserModel, PasswordResetCode, EmailChangeCode

@admin.register(UserModel)
class UserModelAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_verified', 'is_active', 'is_staff', 'user_registered_at')
    search_fields = ('email', 'first_name', 'last_name')
    list_filter = ('is_active', 'is_staff')
    ordering = ('-user_registered_at',)

@admin.register(PasswordResetCode)
class PasswordResetCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at')
    search_fields = ('user__email', 'code')
    list_filter = ('created_at',)
    #readonly_fields = ('token', 'created_at')

@admin.register(EmailChangeCode)
class EmailChangeCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'email', 'code', 'created_at')
    search_fields = ('user__email', 'email', 'code')
    list_filter = ('created_at',)
    #readonly_fields = ('email', 'token', 'created_at')
