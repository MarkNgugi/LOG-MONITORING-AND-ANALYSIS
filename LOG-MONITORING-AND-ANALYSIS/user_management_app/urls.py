from django.urls import path
from . import views


urlpatterns=[

    path('useraccounts/',views.useraccounts,name='useraccounts'),


    path('profile-settings',views.profilesettings,name='profilesettings')
]