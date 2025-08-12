import os
import json
import hmac
import hashlib
from functools import wraps

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required

from .forms import RegisterForm, LoginForm, ChangePasswordForm
from .models import SecureUser

def secure_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('secure_user_id'):
            return redirect(f'/login/?next={request.path}')
        return view_func(request, *args, **kwargs)
    return wrapper

def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

def is_valid_password(password, config):
    if len(password) < config["password_min_length"]:
        return False
    if config["require_uppercase"] and not any(c.isupper() for c in password):
        return False
    if config["require_lowercase"] and not any(c.islower() for c in password):
        return False
    if config["require_digit"] and not any(c.isdigit() for c in password):
        return False
    if config["require_special"] and not any(c in "!@#$%^&*()_+-=[]{},.?" for c in password):
        return False
    if password in config["blocked_passwords"]:
        return False
    return True

def register_view(request):
    config = load_config()

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            # Check your custom password policy
            if not is_valid_password(password, config):
                messages.error(request, "Password does not meet security requirements.")
                return render(request, 'accounts/register.html', {'form': form})

            # Create the user with Django's secure hashing
            SecureUser.objects.create_user(
                username=username,
                email=email,
                password=password
            )

            messages.success(request, "User registered successfully.")
            return redirect('login')  # redirect to login instead of register
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    config = load_config()
    max_attempts = config.get("login_attempts_limit", 3)

    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        try:
            user = SecureUser.objects.get(username=username)
        except SecureUser.DoesNotExist:
            messages.error(request, "User not found.")
            return render(request, 'accounts/login.html', {'form': form})

        if user.login_attempts >= max_attempts:
            messages.error(request, "Account locked after too many failed login attempts.")
            return render(request, 'accounts/login.html', {'form': form})

        auth_user = authenticate(request, username=username, password=password)

        if auth_user is not None:
            user.login_attempts = 0
            user.save()
            login(request, auth_user)  # Django handles the session
            messages.success(request, "Login successful.")
            return redirect(request.GET.get('next', 'profile'))
        else:
            user.login_attempts += 1
            user.save()
            remaining = max_attempts - user.login_attempts
            if remaining > 0:
                messages.error(request, f"Invalid password. {remaining} attempts left.")
            else:
                messages.error(request, "Account locked after too many failed attempts.")

    return render(request, 'accounts/login.html', {'form': form})


@login_required
def change_password_view(request):
    config = load_config()

    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user = request.user
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password']

            # Check old password using Django's method
            if not user.check_password(old_password):
                messages.error(request, "Old password is incorrect.")
                return render(request, 'accounts/change_password.html', {'form': form})

            # Validate new password against your custom policy
            if not is_valid_password(new_password, config):
                messages.error(request, "New password does not meet security requirements.")
                return render(request, 'accounts/change_password.html', {'form': form})

            # Set the new password securely
            user.set_password(new_password)
            user.save()

            messages.success(request, "Password changed successfully.")
            return redirect('profile')
    else:
        form = ChangePasswordForm()

    return render(request, 'accounts/change_password.html', {'form': form})