import os
import json
import hmac
import hashlib
import secrets
from functools import wraps

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.conf import settings
from django.db import IntegrityError

from .forms import RegisterForm, LoginForm, ChangePasswordForm, CustomerForm, ForgotPasswordForm, ResetPasswordForm
from .models import SecureUser, Customer, PasswordResetToken

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

            if not is_valid_password(password, config):
                messages.error(request, "Password does not meet security requirements.")
                return render(request, 'accounts/register.html', {'form': form})

            try:
                SecureUser.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                messages.success(request, "User registered successfully. Please log in.")
                return redirect('login')
            except IntegrityError:
                messages.error(request, "Username or email already exists. Please choose different credentials.")
                return render(request, 'accounts/register.html', {'form': form})
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
            login(request, auth_user)
            messages.success(request, "Login successful.")
            return redirect('add_customer')
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

            if not user.check_password(old_password):
                messages.error(request, "Old password is incorrect.")
                return render(request, 'accounts/change_password.html', {'form': form})

            if not is_valid_password(new_password, config):
                messages.error(request, "New password does not meet security requirements.")
                return render(request, 'accounts/change_password.html', {'form': form})

            user.set_password(new_password)
            user.save()

            logout(request)

            messages.success(request, "Password changed successfully. Please log in again.")
            return redirect('login')
    else:
        form = ChangePasswordForm()

    return render(request, 'accounts/change_password.html', {'form': form})

@login_required
def add_customer_view(request):
    if request.method == 'POST':
        form = CustomerForm(request.POST)
        if form.is_valid():
            customer = form.save()
            messages.success(request, f'New customer added: {customer.first_name} {customer.last_name}')
            return redirect('add_customer')
    else:
        form = CustomerForm()

    customers = Customer.objects.all().order_by('-created_at')

    return render(request, 'accounts/add_customer.html', {
        'form': form,
        'customers': customers
    })

def forgot_password_view(request):
    """Forgot password - step 1: enter email and receive token via email."""
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            try:
                user = SecureUser.objects.get(email=email)

                # Generate random token using SHA-1
                random_value = secrets.token_hex(32)
                token = hashlib.sha1(random_value.encode()).hexdigest()

                PasswordResetToken.objects.create(
                    user=user,
                    token=token
                )

                subject = "Password Reset - Comunication_LTD"
                message = (
                    f"Hello {user.username},\n\n"
                    f"We received a request to reset your password.\n"
                    f"Your reset code is: {token}\n\n"
                    f"This code is valid for one hour.\n\n"
                    f"If you did not request a password reset, you can ignore this email.\n\n"
                    f"Regards,\nComunication_LTD Team"
                )

                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

                messages.success(request, "A reset code has been sent to your email address.")
                return redirect('reset_password')

            except SecureUser.DoesNotExist:
                messages.error(request, "No user found with that email address.")
    else:
        form = ForgotPasswordForm()

    return render(request, 'accounts/forgot_password.html', {'form': form})

def reset_password_view(request):
    """Forgot password - step 2: enter code and new password."""
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            new_password = form.cleaned_data['new_password']

            try:
                reset_token = PasswordResetToken.objects.get(
                    token=token,
                    used=False
                )

                if reset_token.is_expired():
                    messages.error(request, "The reset code has expired. Please request a new one.")
                    return redirect('forgot_password')

                user = reset_token.user
                user.set_password(new_password)
                user.save()

                reset_token.used = True
                reset_token.save()

                messages.success(request, "Your password has been reset. Please log in with your new password.")
                return redirect('login')

            except PasswordResetToken.DoesNotExist:
                messages.error(request, "Invalid or already used reset code.")
    else:
        form = ResetPasswordForm()

    return render(request, 'accounts/reset_password.html', {'form': form})