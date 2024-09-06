import random
import string
from django.db.models.signals import pre_save, post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import UserModel

def send_otp_email(first_name, email, otp):
    """Send OTP to the user's email"""
    verification_link = f"http://{settings.SITE_DOMAIN}/api/verify-otp/"
    send_mail(
        'Verify Your Email Address',
        f'Hi {first_name},\n\n'
        f'Your OTP code is {otp}. Verify your email by visiting the following link: {verification_link}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

def send_password_reset_email(email, token):
    """Send password reset email"""
    reset_link = f"http://{settings.SITE_DOMAIN}/api/password-reset/{token}/"
    send_mail(
        'Password Reset Request',
        f'You requested a password reset. Click the link below to reset your password:\n\n{reset_link}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

# @receiver(post_save, sender=UserModel)
# def handle_user_creation(sender, instance, created, **kwargs):
#     if created:
#         otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
#         otp_expiry = timezone.now() + timezone.timedelta(minutes=60)

#         instance.otp = otp
#         instance.otp_expiry = otp_expiry
#         instance.save()

#         send_otp_email(instance.first_name, instance.email, otp)

@receiver(post_save, sender=UserModel)
def handle_password_reset(sender, instance, **kwargs):
    if instance.reset_password_token and instance.reset_password_token_expiry:
        send_password_reset_email(instance.email, instance.reset_password_token)

@receiver(pre_save, sender=UserModel)
def modify_user_before_save(sender, instance, **kwargs):
    if instance.pk: 
        instance.email = instance.email.lower()

@receiver(pre_delete, sender=UserModel)
def user_about_to_be_deleted(sender, instance, **kwargs):
    print(f"User {instance.email} is about to be deleted.")

