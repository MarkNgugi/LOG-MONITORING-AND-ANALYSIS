from django.urls import path
from . import views

urlpatterns=[

    path('predictive-analysis/',views.predictiveanalysis,name='predictiveanalysis'),
    path('autoincidentresponse/',views.autoincidentresponse,name='autoincidentresponse'),
    path('logclassification/',views.logclassification,name='logclassification'),
    path('logclassification/',views.AImodels,name='AImodels'),
    path('logclassification/',views.modeltraining,name='modeltraining'),
    path('logclassification/',views.modelperformance,name='modelperformance'),
]