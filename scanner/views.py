from __future__ import annotations

import magic
from django.conf import settings
from django.urls import reverse_lazy
from django.views.generic import FormView, DetailView, ListView, TemplateView

from mlapp.inference import infer
from scanner.forms import UploadFileForm
from scanner.models import Scan, Sample
from scanner.utils import sha256_file


class HomeView(TemplateView):
    template_name = "scanner/home.html"


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
    model = Scan
    template_name = "scanner/history.html"
    context_object_name = "scans"
    paginate_by = 20
    ordering = ["-created_at"]
