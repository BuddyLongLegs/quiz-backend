from django.urls import path
from . import views

urlpatterns=[
    path("signup", views.newUser),
    path("login", views.authUser),
    path("game", views.game),
    path("leaderboard", views.leaderboard),
    path("logout", views.logout),
    path("home", views.dashboard),
    path("", views.home)
]