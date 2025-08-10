import os
import json
import hmac, hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import RegisterForm, LoginForm
from .forms import ChangePasswordForm
from .models import SecureUser

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

            if not is_valid_password(password, config):
                messages.error(request, "Password does not meet security requirements.")
                return render(request, 'accounts/register.html', {'form': form})

            salt = os.urandom(16)
            h = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

            SecureUser.objects.create(
                username=username,
                email=email,
                password_hash=h,
                salt=salt
            )

            messages.success(request, "User registered successfully.")
            return redirect('register')
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

        user = SecureUser.objects.filter(username=username).first()
        if not user:
            messages.error(request, "User not found.")
            return render(request, 'accounts/login.html', {'form': form})

        if user.login_attempts >= max_attempts:
            messages.error(request, "Account locked after too many failed login attempts.")
            return render(request, 'accounts/login.html', {'form': form})

        computed_hash = hmac.new(user.salt, password.encode(), hashlib.sha256).hexdigest()
        if computed_hash == user.password_hash:
            user.login_attempts = 0
            user.save()
            messages.success(request, "Login successful.")
            # נשארים באותו עמוד ומציגים את ההודעה
        else:
            user.login_attempts += 1
            user.save()
            remaining = max_attempts - user.login_attempts
            if remaining > 0:
                messages.error(request, f"Invalid password. {remaining} attempts left.")
            else:
                messages.error(request, "Account locked after too many failed attempts.")

    return render(request, 'accounts/login.html', {'form': form})

@login_required(login_url='/login/')
def change_password_view(request):
    config = load_config()

    if request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user = request.user
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password']

            salt = user.salt
            h = hmac.new(salt, old_password.encode(), hashlib.sha256).hexdigest()
            if h != user.password_hash:
                messages.error(request, "Old password is incorrect.")
                return render(request, 'accounts/change_password.html', {'form': form})

            new_salt = os.urandom(16)
            new_hash = hmac.new(new_salt, new_password.encode(), hashlib.sha256).hexdigest()

            user.salt = new_salt
            user.password_hash = new_hash
            user.save()

            messages.success(request, "Password changed successfully.")
            return redirect('profile') 
    else:
        form = ChangePasswordForm()

    return render(request, 'accounts/change_password.html', {'form': form})