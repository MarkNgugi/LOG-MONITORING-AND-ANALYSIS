from django.urls import path
from . import views


urlpatterns=[

    path('useraccounts/',views.useraccounts,name='useraccounts'),


    path('profile-settings',views.profilesettings,name='profilesettings'),
    path('accountsecurity/',views.accountsecurity,name='accountsecurity'),
    path('profilesecurity/',views.profilesecurity,name='profilesecurity'),
    path('profilenotifications/',views.profilenotifications,name='profilenotifications'),
    path('iplist/',views.ip_page,name='ip_page'),
    path('test/',views.test,name='test'),

]