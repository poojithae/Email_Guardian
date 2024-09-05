from django.urls import path, include
from .views import (
    RegisterViewSet,
    VerifyOTPViewSet,
    RegenerateOTPViewSet,
    LoginViewSet,
    LogoutViewSet,
    PasswordResetViewSet,
    PasswordResetVerifyViewSet,
    PasswordResetVerifiedViewSet,
    EmailChangeViewSet,
    EmailChangeVerifyViewSet,
    PasswordChangeViewSet
    
)
from .views import UserCSVExportView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt import views as jwt_views


router = DefaultRouter()
router.register(r'register', RegisterViewSet, basename='register')
router.register(r'verify-otp', VerifyOTPViewSet, basename='verify-otp')
router.register(r'regenerate-otp', RegenerateOTPViewSet, basename='regenerate-otp')
router.register(r'login', LoginViewSet, basename='login')
router.register(r'logout', LogoutViewSet, basename='logout')
router.register(r'password-reset', PasswordResetViewSet, basename='password-reset')
router.register(r'password-reset-verify', PasswordResetVerifyViewSet, basename='password-reset-verify')
router.register(r'password-reset-verified', PasswordResetVerifiedViewSet, basename='password-reset-verified')
router.register(r'email-change', EmailChangeViewSet, basename='email-change')
router.register(r'email-change-verify', EmailChangeVerifyViewSet, basename='email-change-verify')
router.register(r'password-change', PasswordChangeViewSet, basename='password-change')


urlpatterns = [
    path('', include(router.urls)),
    #path('regenerate-otp/<int:user_id>/', RegenerateOTPViewSet.as_view(), name='regenerate-otp'),
    #path('token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    #path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('export-csv/', UserCSVExportView.as_view(), name='export-csv'),
    #path('profile/', profile_view, name='profile_view'),
    
]