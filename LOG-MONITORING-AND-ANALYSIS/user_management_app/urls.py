from django.urls import path
from . import views


urlpatterns=[ 

    path('useraccounts/',views.user_list,name='useraccounts'),
    path('add-user/', views.add_user, name='add_user'),
    path('edit-user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),


    path('account-settings/',views.accountsettings,name='accountsettings'),

    path('iplist/',views.ip_page,name='ip_page'),
    path('test/',views.test,name='test'),

]