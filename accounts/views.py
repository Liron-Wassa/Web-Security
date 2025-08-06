import os
import json
import hmac, hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import RegisterForm
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
