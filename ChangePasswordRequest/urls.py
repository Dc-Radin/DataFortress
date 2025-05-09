from django.urls import path
from . import views

urlpatterns = [
    # Change Password URLs
    path('change-password/', views.change_password, name='change_password'),
    path('api/change-password/', views.PasswordChangeAPIView.as_view(), name='api_change_password'),
    
    # Forgot Password URLs
    path('reset-password/', views.password_reset_request, name='password_reset'),
    path('reset-password/done/', views.password_reset_done, name='password_reset_done'),
    path('reset-password/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('reset-password/complete/', views.password_reset_complete, name='password_reset_complete'),
    
    # API Forgot Password URLs
    path('api/reset-password/', views.PasswordResetAPIView.as_view(), name='api_password_reset'),
    path('api/reset-password/confirm/', views.PasswordResetConfirmAPIView.as_view(), name='api_password_reset_confirm'),
]