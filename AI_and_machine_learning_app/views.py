from django.shortcuts import render

def predictiveanalysis(request):
    context={}
    return render(request,'baseapp/predictiveanalysis/predictiveanalysis.html',context)

def autoincidentresponse(request):
    context={}
    return render(request,'baseapp/autoIR/autoIR.html',context)

def logclassification(request):
    context={}
    return render(request,'baseapp/logclassification/logclassification.html',context)

def AImodels(request):
    context={}
    return render(request,'baseapp/AImodels/Aimodels.html',context)

def modeltraining(request):
    context={}
    return render(request,'baseapp/modeltraining/modeltraining.html',context)

def modelperformance(request):
    context={}
    return render(request,'baseapp/modelperformance/modelperformance.html',context)