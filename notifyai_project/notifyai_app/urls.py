from django.urls import path
from . import views
from django.shortcuts import render
from .views import logout_view

urlpatterns = [
    path('', views.home,name='home'),
    path('login/', views.google_login, name='google_login'),
    path('auth/callback/', views.auth_callback, name='auth_callback'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('process_prompt/', views.process_prompt, name='process_prompt'),
    path('logout/', views.logout_view, name='logout'),
]
