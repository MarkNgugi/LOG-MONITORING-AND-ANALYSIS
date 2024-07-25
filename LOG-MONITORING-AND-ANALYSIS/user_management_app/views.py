from django.shortcuts import render
from django.http import HttpResponse

def simple(request):
    return HttpResponse("This is the first page")
