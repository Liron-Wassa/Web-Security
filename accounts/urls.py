from django.urls import path
from .views import register_view, login_view 
from .views import change_password_view 

urlpatterns = [
    path('register/', register_view, name='register'),
    path('change-password/', change_password_view, name='change_password'),
    path('login/', login_view, name='login'),
    path('accounts/login/', login_view, name='login'),
]
