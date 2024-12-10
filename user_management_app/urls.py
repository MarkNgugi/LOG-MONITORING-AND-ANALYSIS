from django.urls import path
from . import views
from log_management_app import urls
 

urlpatterns=[ 
    path('home/',views.home,name='home'),

    path('login/',views.custom_login,name='login'),
    path('register/',views.register,name='register'),
    path('logout/', views.custom_logout, name='logout'),


    path('account-settings/', views.accountsettings, name='accountsettings'),
    path('account-settings/<str:tab>/', views.accountsettings, name='accountsettings_tab'),


] 