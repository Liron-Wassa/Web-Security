from django.db import models

class SecureUser(models.Model):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=128)
    salt = models.BinaryField()

    def __str__(self):
        return self.username
