from django.http import HttpResponseRedirect, HttpResponseBadRequest
from django.shortcuts import render
from django import forms
from django.conf import settings

import os
from dotenv import load_dotenv
load_dotenv()
import hashlib
import jwt
from datetime import datetime, timedelta

tokenHandler = jwt
JWT_SECRET = os.environ.get("JWT_SECRET")

def set_cookie(response, key, value):
    max_age = 60 * 60 # 1 hour
    expires = datetime.strftime(
        datetime.utcnow() + timedelta(seconds=max_age),
        "%a, %d-%b-%Y %H:%M:%S GMT",
    )
    response.set_cookie(
        key,
        tokenHandler.encode(value, JWT_SECRET, algorithm="HS256"),
        max_age=max_age,
        expires=expires,
        domain=settings.SESSION_COOKIE_DOMAIN,
        secure=settings.SESSION_COOKIE_SECURE or None,
    )

from .models import User

class newUserForm(forms.Form):
    name = forms.CharField(max_length=64, label="Your Name")
    username = forms.CharField(max_length=32, strip=True, label="Username")
    password = forms.CharField(max_length=32)


class loginUserForm(forms.Form):
    username = forms.CharField(max_length=32, strip=True, label="Username")
    password = forms.CharField(max_length=32)

# Register your models here.
def newUser(req):
    if(req.method == "GET"):
        return render(req, 'signup.html', {'form': newUserForm()})

    if(req.method == "POST"):
        form = newUserForm(req.POST)
        if form.is_valid():
            try:
                User.objects.create(
                    name=form.cleaned_data["name"],
                    username=form.cleaned_data["username"],
                    hash=hashlib.sha256(form.cleaned_data["password"].encode('utf-8')).hexdigest()
                )
            except Exception as e:
                return HttpResponseBadRequest({"error": e})
            
            return HttpResponseRedirect("/login")
        return render(req, 'signup.html', {'form': newUserForm(), "error": "Invalid Form Data"})
    return HttpResponseBadRequest({"error": "Invalid Method"})


def authUser(req):
    auth = req.COOKIES.get("secret")
    if(auth is not None):
        message = tokenHandler.decode(auth.split(";")[0], JWT_SECRET, algorithms="HS256")
        if (datetime.fromisoformat(message["expireon"]) > datetime.now()) :
            return HttpResponseRedirect("/")
        
    if(req.method=="GET"):
        return render(req, 'login.html', {'form': loginUserForm()})

    if(req.method=="POST"):
        form = loginUserForm(req.POST)
        if form.is_valid():
            hash = hashlib.sha256(form.cleaned_data["password"].encode('utf-8')).hexdigest()
            user = User.objects.filter(
                username__exact = form.cleaned_data["username"],
                hash__exact = hash
            ).first()
            if(user):
                res = HttpResponseRedirect("/home")
                data = {
                    "username": user.username,
                    "expireon": str(datetime.now() + timedelta(hours=1))
                }
                set_cookie(res, "secret", data)
                return res
            return HttpResponseRedirect("/login")
    return HttpResponseBadRequest({"error": "Invalid Method"})


scores = {
    "a" : 1,
    "b" : 2,
    "c" : 5,
    "d" : 10
}

def game(req):
    auth = req.COOKIES.get("secret")
    if(auth is not None):
        message = tokenHandler.decode(auth.split(";")[0], JWT_SECRET, algorithms="HS256")
        if (datetime.fromisoformat(message["expireon"]) > datetime.now()) :
            user = User.objects.filter(username__exact= message["username"]).first()
        else:
            return HttpResponseRedirect("/login")
    else:
        return HttpResponseRedirect("/login")
    
    if(req.method == "GET"):
        return render(req, "game.html", {"user": user, "page": "game"})
    
    if(req.method == "POST"):
        if(req.POST["answer"] in scores.keys()):
            user.score += scores[req.POST["answer"]]
            user.save()
            return HttpResponseRedirect("/home")
        
        return render(req, "game.html", {"user": user, "error": "Invalid Option", "page": "game"})
    return HttpResponseBadRequest({"error": "Invalid Method"})

def leaderboard(req):
    auth = req.COOKIES.get("secret")
    if(auth is not None):
        message = tokenHandler.decode(auth.split(";")[0], JWT_SECRET, algorithms="HS256")
        if (datetime.fromisoformat(message["expireon"]) > datetime.now()) :
            user = User.objects.filter(username__exact= message["username"]).first()
        else:
            user = None
    else:
        user=None

    board = User.objects.filter().order_by("-score")
    return render(req, "leaderboard.html", {"user": user, "board": board, "page": "board", "i": 0})

def home(req):
    auth = req.COOKIES.get("secret")
    if(auth is not None):
        message = tokenHandler.decode(auth.split(";")[0], JWT_SECRET, algorithms="HS256")
        if (datetime.fromisoformat(message["expireon"]) > datetime.now()) :
            user = User.objects.filter(username__exact= message["username"]).first()
        else:
            user = None
    else:
        user=None
    
    return render(req, "index.html", {"user": user, "page": "home"})

def logout(req):
    res = HttpResponseRedirect("/")
    res.delete_cookie("secret")
    return res

def dashboard(req):
    auth = req.COOKIES.get("secret")
    if(auth is not None):
        message = tokenHandler.decode(auth.split(";")[0], JWT_SECRET, algorithms="HS256")
        if (datetime.fromisoformat(message["expireon"]) > datetime.now()) :
            user = User.objects.filter(username__exact= message["username"]).first()
            return render(req, "home.html", {"user": user, "page": "dashboard"})
    
    return HttpResponseRedirect("/login")
    
    