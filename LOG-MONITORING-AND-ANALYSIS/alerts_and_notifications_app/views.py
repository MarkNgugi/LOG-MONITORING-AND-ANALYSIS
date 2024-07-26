from django.shortcuts import render

#ALERTS

def alertspage(request):
    context={}
    return render(request,'baseapp/alerts/alerts.html',context)

def scheduledreports(request):
    context={}
    return render(request,'baseapp/scheduledreports/scheduledreports.html',context)

def addscheduledreport(request):
    context={}
    return render(request,'baseapp/scheduledreports/addreport.html',context)
    
