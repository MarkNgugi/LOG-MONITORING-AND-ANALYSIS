from django.shortcuts import render

#ALERTS

def alertconfig(request):
    context={}
    return render(request,'baseapp/alertconfig/alertconfig.html',context)

def alertspage(request):
    context={}
    return render(request,'baseapp/alerts/alerts.html',context)
    

def scheduledreports(request):
    context={}
    return render(request,'baseapp/scheduledreports/scheduledreports.html',context)

def addscheduledreport(request):
    context={}
    return render(request,'baseapp/scheduledreports/addreport.html',context)
    
def customalerts(request):
    context={}
    return render(request,'baseapp/customalerts/customalerts.html',context)

def notification_settings(request):
    context={}
    return render(request,'baseapp/notificationsettings/notsettings.html',context)