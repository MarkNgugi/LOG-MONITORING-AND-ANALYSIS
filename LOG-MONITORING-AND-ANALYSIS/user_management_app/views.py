from django.shortcuts import render


def useraccounts(request):
    context={}
    return render(request,'baseapp/useraccounts/useraccounts.html',context)

def profilesettings(request):
    context={}
    return render(request,'baseapp/profilesettings/profilesettings.html',context)

def accountsecurity(request):
    context={}
    return render(request,'baseapp/profilesettings/accountsettings.html',context)

def profilesecurity(request):
    context={}
    return render(request,'baseapp/profilesettings/profilesecurity.html',context)

def profilenotifications(request):
    context={}
    return render(request,'baseapp/profilesettings/profilenotifications.html',context)

def ip_page(request):
    context={}
    return render(request,'baseapp/accesscontrol/ip.html',context)


