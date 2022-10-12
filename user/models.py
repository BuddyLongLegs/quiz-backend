from email.policy import default
from django.db import models

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=64)
    username = models.CharField(max_length=32, primary_key=True)
    created = models.DateTimeField(auto_now_add=True)
    score = models.IntegerField(default=0)
    hash = models.CharField(max_length=300)

