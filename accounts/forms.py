from django import forms
import json
from .models import Customer

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=50)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput())

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput(), label="Old Password")
    new_password = forms.CharField(widget=forms.PasswordInput(), label="New Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label="Confirm New Password")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open("config.json", "r") as f:
            self.config = json.load(f)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New password and confirmation do not match.")
        return cleaned_data

    def clean_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        config = self.config

        if not new_password:
            return new_password  

        if len(new_password) < config.get("password_min_length", 10):
            raise forms.ValidationError(f"Password must be at least {config['password_min_length']} characters long.")
        if config.get("require_uppercase", True) and not any(c.isupper() for c in new_password):
            raise forms.ValidationError("Password must include at least one uppercase letter.")
        if config.get("require_lowercase", True) and not any(c.islower() for c in new_password):
            raise forms.ValidationError("Password must include at least one lowercase letter.")
        if config.get("require_digit", True) and not any(c.isdigit() for c in new_password):
            raise forms.ValidationError("Password must include at least one digit.")
        if config.get("require_special", True) and not any(c in "!@#$%^&*()_+-=[]{},.?" for c in new_password):
            raise forms.ValidationError("Password must include at least one special character.")
        if new_password.lower() in [p.lower() for p in config.get("blocked_passwords", [])]:
            raise forms.ValidationError("This password is blocked. Please choose another.")
        return new_password

class LoginForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(widget=forms.PasswordInput())

class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['first_name', 'last_name', 'email', 'phone', 'address']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last name'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Phone'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Address', 'rows': 3}),
        }

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )

class ResetPasswordForm(forms.Form):
    token = forms.CharField(
        max_length=64,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter the reset code you received'})
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New password'}),
        label="New Password"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm new password'}),
        label="Confirm New Password"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open("config.json", "r") as f:
            self.config = json.load(f)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New password and confirmation do not match.")
        return cleaned_data

    def clean_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        config = self.config

        if not new_password:
            return new_password  

        if len(new_password) < config.get("password_min_length", 10):
            raise forms.ValidationError(f"Password must be at least {config['password_min_length']} characters long.")
        if config.get("require_uppercase", True) and not any(c.isupper() for c in new_password):
            raise forms.ValidationError("Password must include at least one uppercase letter.")
        if config.get("require_lowercase", True) and not any(c.islower() for c in new_password):
            raise forms.ValidationError("Password must include at least one lowercase letter.")
        if config.get("require_digit", True) and not any(c.isdigit() for c in new_password):
            raise forms.ValidationError("Password must include at least one digit.")
        if config.get("require_special", True) and not any(c in "!@#$%^&*()_+-=[]{},.?" for c in new_password):
            raise forms.ValidationError("Password must include at least one special character.")
        if new_password.lower() in [p.lower() for p in config.get("blocked_passwords", [])]:
            raise forms.ValidationError("This password is blocked. Please choose another.")
        return new_password