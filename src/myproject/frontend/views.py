# frontend/views.py

from django.shortcuts import render

def login_view(request):
    return render(request, 'login.html')

def signup_view(request):
    return render(request, 'signup.html')

# views.py (Django)
from django.contrib.auth.decorators import login_required
from .models import Chat

def chat_view(request):
    return render(request, 'chat.html')
