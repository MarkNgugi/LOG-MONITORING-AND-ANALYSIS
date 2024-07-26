from django.shortcuts import render

#ALERTS

def alertspage(request):
    context={}
    return render(request,'baseapp/alerts/alerts.html',context)
