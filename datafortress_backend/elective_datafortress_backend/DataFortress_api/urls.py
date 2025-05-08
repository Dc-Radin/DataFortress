from django.urls import path
from . import views

urlpatterns = [  
    path('DataFortress/', views.say_hello)  
]