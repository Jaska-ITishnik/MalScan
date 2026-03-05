from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path, include
from django.views.generic import TemplateView

from root.settings import STATIC_URL, STATIC_ROOT, MEDIA_URL, MEDIA_ROOT

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("scanner.urls")),
    # path('', TemplateView.as_view(template_name='account/index.html')),
    path('accounts/', include('allauth.urls')),
    path('logout/', LogoutView.as_view())

]

if settings.DEBUG:
    urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT) + static(STATIC_URL, document_root=STATIC_ROOT)
