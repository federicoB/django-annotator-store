from django.conf.urls import include, url
from annotator_store import views as annotation_views

urlpatterns = [
    # annotations
    url(r'^annotations/api/', include('annotator_store.urls', namespace='annotation-api')),
    # annotatorjs doesn't handle trailing slash in api prefix url
    url(r'^annotations/api', annotation_views.AnnotationIndex.as_view(), name='annotation-api-prefix'),
]