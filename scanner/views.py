import json
from pathlib import Path

import magic
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout, login
from django.db.models import Q, Count
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import FormView, DetailView, ListView, TemplateView, CreateView

from mlapp.inference import infer
from scanner.forms import UploadFileForm, LoginModelForm, RegisterModelFrom
from scanner.models import Scan, Sample
from scanner.utils import sha256_file


def privacy_policy(request):
    return render(request, "scanner/privacy.html")


def terms_of_service(request):
    return render(request, "scanner/terms.html")


class RegisterFormView(CreateView):
    template_name = "account/register.html"
    form_class = RegisterModelFrom
    success_url = reverse_lazy("scanner:login")

    def form_valid(self, form):
        text = "Вы успешно зарегистрировались в систему📣"
        messages.add_message(self.request, messages.WARNING, text)
        return super().form_valid(form)

    def form_invalid(self, form):
        text = "⚠Пользователь с таким именем пользователя уже существует."
        messages.add_message(self.request, messages.WARNING, text)
        return super().form_invalid(form)


class LoginRegisterView(FormView):
    template_name = 'account/login.html'
    form_class = LoginModelForm

    def form_valid(self, form):
        user = form.get_user()
        login(self.request, user)
        text = "Вы успешно вошли в систему📣"
        messages.add_message(self.request, messages.WARNING, text)
        return redirect('scanner:home')

    def form_invalid(self, form):
        text = form.errors['__all__'][0]
        messages.add_message(self.request, messages.WARNING, text)
        return super().form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('scanner:home')
        return super().dispatch(request, *args, **kwargs)


class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('scanner:home')


class HomeView(TemplateView):
    template_name = "scanner/home.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        # 1) dataset stats (from model_meta.json)
        meta_path = Path(settings.BASE_DIR) / "artifacts" / "model_meta.json"
        dataset_stats = []
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                dataset_stats = meta.get("dataset_stats", [])
            except Exception:
                dataset_stats = []
        ctx["dataset_stats"] = dataset_stats

        # 2) live uploads stats from DB (Samples)
        rows = (
            Sample.objects
            .values("detected_type")
            .annotate(total=Count("id"))
            .order_by("-total")
        )
        # normalize empty type
        live = []
        total_all = 0
        for r in rows:
            t = r["detected_type"] or "OTHER"
            c = r["total"]
            total_all += c
            live.append({"type": t, "total": c})
        ctx["live_stats"] = live
        ctx["live_total"] = total_all

        return ctx


class UploadScanView(FormView):
    template_name = "scanner/upload.html"
    form_class = UploadFileForm
    success_url = reverse_lazy("scanner:history")

    def form_valid(self, form):
        uploaded = form.cleaned_data["file"]

        sample = Sample.objects.create(
            original_name=uploaded.name,
            stored_file=uploaded,
            size_bytes=uploaded.size,
            owner=self.request.user if self.request.user.is_authenticated else None,
            device_id="" if self.request.user.is_authenticated else getattr(self.request, "device_id", ""),
            sha256="",
            mime_type="",
            detected_type="",
        )

        file_path = sample.stored_file.path
        sample.sha256 = sha256_file(file_path)
        try:
            sample.mime_type = magic.from_file(file_path, mime=True) or ""
        except Exception:
            sample.mime_type = ""
        sample.save()

        res = infer(
            file_path=file_path,
            mime_type=sample.mime_type,
            apk_model_path=settings.APK_MODEL_PATH,
            pdf_model_path=settings.PDF_MODEL_PATH,
        )

        sample.detected_type = res.detected_type
        sample.save(update_fields=["detected_type"])

        scan = Scan.objects.create(
            sample=sample,
            score_percent=res.score_percent,
            verdict=res.verdict,
            model_used=res.model_used,
            model_version="v1",
            reasons_json=res.reasons,
        )

        self.success_url = reverse_lazy("scanner:scan_detail", kwargs={"pk": scan.id})
        return super().form_valid(form)


class ScanDetailView(DetailView):
    model = Scan
    template_name = "scanner/scan_detail.html"
    context_object_name = "scan"


class HistoryView(ListView):
    queryset = Scan.objects.all()
    template_name = "scanner/history.html"
    context_object_name = "scans"
    paginate_by = 20
    ordering = "-created_at",

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        device_id = getattr(self.request, "device_id", "")
        if user.is_authenticated:
            if device_id:
                return qs.filter(Q(sample__owner=user) | Q(sample__device_id=device_id))
            return qs.filter(Q(sample__owner=user))
        if not device_id:
            return qs.none()
        return qs.filter(sample__owner__isnull=True, sample__device_id=device_id)
