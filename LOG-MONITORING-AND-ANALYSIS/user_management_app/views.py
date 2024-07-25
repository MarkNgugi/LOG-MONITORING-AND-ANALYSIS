from django.shortcuts import render


def useraccounts(request):
    context={}
    return render(request,'baseapp/useraccounts/useraccounts.html',context)

def profilesettings(request):
    context={}
    return render(request,'baseapp/profilesettings/profilesettings.html',context)

