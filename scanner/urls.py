from django.urls import path

from .views import HomeView, UploadScanView, ScanDetailView, HistoryView, LoginRegisterView, LogoutView, \
    RegisterFormView, privacy_policy, terms_of_service

app_name = "scanner"

urlpatterns = [

    # auth
    path("register/", RegisterFormView.as_view(), name="register"),
    path("login/", LoginRegisterView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("privacy/", privacy_policy, name="privacy"),
    path("terms/", terms_of_service, name="terms"),
    path("", HomeView.as_view(), name="home"),
    path("scan/", UploadScanView.as_view(), name="upload"),
    path("history/", HistoryView.as_view(), name="history"),
    path("scan/<int:pk>/", ScanDetailView.as_view(), name="scan_detail"),
]
