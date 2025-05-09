from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Your old password was entered incorrectly. Please enter it again.")
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': "The two password fields didn't match."})
        
        # Validate the password against Django's password validators
        validate_password(data['new_password1'], self.context['request'].user)
        
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password1'])
        user.save()
        
        # Update session to prevent logout
        update_session_auth_hash(self.context['request'], user)
        
        return user

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        # We don't check if the user exists here for security reasons
        # The view will handle this logic without exposing whether the email exists
        return value

    def save(self):
        email = self.validated_data['email']
        users = User.objects.filter(email=email)
        
        if users.exists():
            user = users[0]
            request = self.context.get('request')
            
            # Generate token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Create reset URL
            domain = request.get_host()
            protocol = 'https' if request.is_secure() else 'http'
            reset_url = f"{protocol}://{domain}/reset-password/{uid}/{token}/"
            
            # Send email
            subject = "Password Reset Requested"
            email_template = "accounts/password_reset_email.html"
            context = {
                "user": user,
                "reset_url": reset_url,
                "site_name": "Your Site",
            }
            email_content = render_to_string(email_template, context)
            
            send_mail(
                subject,
                email_content,
                settings.DEFAULT_FROM_EMAIL,
                [user.email]
            )
        
        # We return True regardless of whether a user was found
        # to avoid revealing whether an email exists in the system
        return True

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password1 = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uid']))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({'uid': 'Invalid user ID'})

        if not default_token_generator.check_token(self.user, data['token']):
            raise serializers.ValidationError({'token': 'Invalid or expired token'})

        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': "The two password fields didn't match."})
        
        validate_password(data['new_password1'], self.user)
        
        return data

    def save(self):
        password = self.validated_data['new_password1']
        self.user.set_password(password)
        self.user.save()
        return self.user