from django.db.models import TextChoices, Model, CharField, FileField, ForeignKey, CASCADE, BigIntegerField, \
    DateTimeField, PositiveIntegerField, JSONField

from scanner.validators import validate_file_size


class Sample(Model):
    original_name = CharField(max_length=255, verbose_name="Fayl nomi")
    stored_file = FileField(upload_to="uploads/%Y/%m/%d/", verbose_name="Fayl", validators=[validate_file_size])
    owner = ForeignKey("auth.User", on_delete=CASCADE, null=True)
    device_id = CharField(max_length=64, blank=True, default="", db_index=True, verbose_name="Device ID")
    size_bytes = BigIntegerField(default=0, verbose_name="Hajm (bayt)")
    sha256 = CharField(max_length=64, blank=True, default="", verbose_name="SHA-256")
    mime_type = CharField(max_length=120, blank=True, default="", verbose_name="MIME")
    detected_type = CharField(max_length=16, blank=True, default="", verbose_name="Turi")
    created_at = DateTimeField(auto_now_add=True, verbose_name="Yaratilgan")

    class Meta:
        verbose_name = "Namuna"
        verbose_name_plural = "Namunalar"

    def __str__(self) -> str:
        return self.original_name


class Scan(Model):
    class VerdictChoice(TextChoices):
        BENIGN = "benign", "Чисто"
        SUSPICIOUS = "suspicious", "Подозрительно"
        MALICIOUS = "malicious", "Вредоносно"
        UNKNOWN = "unknown", "Неизвестно"

    sample = ForeignKey(Sample, on_delete=CASCADE, related_name="scans", verbose_name="Namuna")
    score_percent = PositiveIntegerField(default=0, verbose_name="Ball (%)")
    verdict = CharField(max_length=16, choices=VerdictChoice.choices, default=VerdictChoice.UNKNOWN,  # noqa
                        verbose_name="Xulosa", )
    model_used = CharField(max_length=32, blank=True, default="", verbose_name="Model")
    model_version = CharField(max_length=32, blank=True, default="v1", verbose_name="Versiya")
    reasons_json = JSONField(default=dict, blank=True, verbose_name="Sabablar")
    created_at = DateTimeField(auto_now_add=True, verbose_name="Tekshiruv vaqti")

    class Meta:
        verbose_name = "Tekshiruv"
        verbose_name_plural = "Tekshiruvlar"

    def __str__(self) -> str:
        return f"{self.sample.original_name} — {self.verdict} ({self.score_percent}%)"
