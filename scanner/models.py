from django.db import models
from django.db.models import TextChoices

from scanner.validators import validate_file_size


class Sample(models.Model):
    original_name = models.CharField(max_length=255, verbose_name="Fayl nomi")
    stored_file = models.FileField(upload_to="uploads/%Y/%m/%d/", verbose_name="Fayl", validators=[validate_file_size])
    size_bytes = models.BigIntegerField(default=0, verbose_name="Hajm (bayt)")
    sha256 = models.CharField(max_length=64, blank=True, default="", verbose_name="SHA-256")
    mime_type = models.CharField(max_length=120, blank=True, default="", verbose_name="MIME")
    detected_type = models.CharField(max_length=16, blank=True, default="", verbose_name="Turi")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Yaratilgan")

    class Meta:
        verbose_name = "Namuna"
        verbose_name_plural = "Namunalar"

    def __str__(self) -> str:
        return self.original_name


class Scan(models.Model):
    class VerdictChoice(TextChoices):
        BENIGN = "benign", "Toza"
        SUSPICIOUS = "suspicious", "Shubhali"
        MALICIOUS = "malicious", "Zararli"
        UNKNOWN = "unknown", "Noma’lum"

    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, related_name="scans", verbose_name="Namuna")
    score_percent = models.IntegerField(default=0, verbose_name="Ball (%)")
    verdict = models.CharField(max_length=16, choices=VerdictChoice.choices, default=VerdictChoice.UNKNOWN,  # noqa
                               verbose_name="Xulosa", )
    model_used = models.CharField(max_length=32, blank=True, default="", verbose_name="Model")
    model_version = models.CharField(max_length=32, blank=True, default="v1", verbose_name="Versiya")
    reasons_json = models.JSONField(default=dict, blank=True, verbose_name="Sabablar")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Tekshiruv vaqti")

    class Meta:
        verbose_name = "Tekshiruv"
        verbose_name_plural = "Tekshiruvlar"

    def __str__(self) -> str:
        return f"{self.sample.original_name} — {self.verdict} ({self.score_percent}%)"
