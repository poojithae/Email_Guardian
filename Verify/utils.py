from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator  
import six
import random
import string

def send_otp(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}.'
    send_mail(
        subject, 
        message, 
        settings.DEFAULT_FROM_EMAIL, 
        [email], 
        fail_silently=False,
    )





# class TokenGenerator(PasswordResetTokenGenerator):  
#     def _make_hash_value(self, user, timestamp):  
#         return (  
#             six.text_type(user.pk) + six.text_type(timestamp) +  
#             six.text_type(user.is_active)  
#         )  
# account_activation_token = TokenGenerator()  