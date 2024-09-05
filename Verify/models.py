from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.validators import RegexValidator, validate_email
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.core.mail import send_mail
import binascii
import os


EXPIRY_PERIOD = 3


phone_regex = RegexValidator(
    regex=r"^\d{10}$", 
    message="Phone number must be 10 digits only."
)

def _generate_code():
    return binascii.hexlify(os.urandom(20)).decode('utf-8')

class UserManager(BaseUserManager):
    def _create_user(self, email, password, is_staff, is_superuser,
                     is_verified, **extra_fields):
        """
        Creates and saves a User with a given email and password.
        """
        now = timezone.now()
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, is_verified=is_verified,
                          last_login=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_user(self, email, password=None, **extra_fields):
        return self._create_user(email, password, False, False, False,
                                 **extra_fields)
    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True, True,
                                 **extra_fields)

class UserModel(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        unique=True,
        max_length=255,
        validators=[validate_email],
        db_index=True,
    )
    phone_number = models.CharField(
        unique=True,
        max_length=10,
        null=True,
        blank=True,
        validators=[phone_regex],
        db_index=True,
    )
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)    
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    max_otp_try = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_max_out = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_verified = models.BooleanField(_('verified'), default=False)
    is_staff = models.BooleanField(default=False)
    user_registered_at = models.DateTimeField(auto_now_add=True)
    reset_password_token = models.CharField(max_length=255, blank=True, null=True, unique=False)
    reset_password_token_expiry = models.DateTimeField(blank=True, null=True)
    
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['first_name', 'last_name']
    

    objects = UserManager()

    def get_full_name(self):
    
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        return self.first_name

    def __str__(self):
        return self.email
    
    def email_user(self, subject, message, from_email=None, **kwargs):
        send_mail(subject, message, from_email, [self.email], **kwargs)
    
    class Meta:
        permissions = [
            ("view_user", "Can view user"),
        ]
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email'),
            models.UniqueConstraint(fields=['phone_number'], name='unique_phone_number'),
        ]


class AbstractBaseCode(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE, db_index=True)
    code = models.CharField(_('code'), max_length=40, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

    
    def send_email(self, subject, message):
        
        from_email = settings.EMAIL_FROM
        send_mail(subject, message, from_email, [self.user.email])
        
    def __str__(self):
        return str(self.code)


class PasswordResetCodeManager(models.Manager):
    def create_password_reset_code(self, user):
        code = _generate_code()
        password_reset_code = self.create(user=user, code=code)
        
        return password_reset_code
    
    def get_expiry_period(self):
        return EXPIRY_PERIOD

class EmailChangeCodeManager(models.Manager):
    def create_email_change_code(self, user, email):
        code = _generate_code()
        email_change_code = self.create(user=user, code=code, email=email)
        return email_change_code
    
    def get_expiry_period(self):
        return EXPIRY_PERIOD
    
class PasswordResetCode(AbstractBaseCode):
    objects = PasswordResetCodeManager()

class EmailChangeCode(AbstractBaseCode):
    email = models.EmailField(_('email address'), max_length=255)

    objects = EmailChangeCodeManager()










