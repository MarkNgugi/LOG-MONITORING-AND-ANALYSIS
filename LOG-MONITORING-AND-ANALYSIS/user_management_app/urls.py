from django.urls import path
from . import views
from log_management_app import urls
 

urlpatterns=[ 
    path('home/',views.home,name='home'),

    path('login/',views.custom_login,name='login'),
    path('register/',views.register,name='register'),
    path('logout/', views.custom_logout, name='logout'),


    path('useraccounts/',views.user_list,name='useraccounts'),
    path('add-user/', views.add_user, name='add_user'),
    path('edit-user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),

    path('user-profile/<int:user_id>/', views.user_profile, name='user_profile'),


    path('account-settings/', views.accountsettings, name='accountsettings'),
    path('account-settings/<str:tab>/', views.accountsettings, name='accountsettings_tab'),

    path('iplist/',views.ip_page,name='ip_page'),
    path('test/',views.test,name='test'),

] 