from pathlib import Path
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "EMBER2024 APK va PDF belgilarini X_*.dat / y_*.dat vektorlariga aylantiradi."

    def add_arguments(self, parser):
        parser.add_argument("--apk_dir", required=True)
        parser.add_argument("--pdf_dir", required=True)
        parser.add_argument("--label_type", default="label")

    def _has_vectorized(self, data_dir: str) -> bool:
        p = Path(data_dir)
        return all((p / name).exists() for name in ("X_train.dat", "y_train.dat", "X_test.dat", "y_test.dat"))

    def _safe_vectorize(self, thrember, data_dir: str, label_type: str, title: str):
        # .dat fayllari mavjud bo‘lsa, qayta vektorlash shart emas.
        if self._has_vectorized(data_dir):
            self.stdout.write(self.style.SUCCESS(f"{title}: vektorlar avvaldan tayyor (X_/y_ .dat mavjud)."))
            return

        self.stdout.write(self.style.WARNING(f"{title} vektorlanmoqda ({label_type})..."))

        try:
            thrember.create_vectorized_features(data_dir, label_type=label_type)
            self.stdout.write(self.style.SUCCESS(f"{title}: vektorlash tugadi."))
            return

        except ValueError as e:
            # challenge JSONL fayli bo‘lmasa, thrember xatolik qaytarishi mumkin.
            msg = str(e)
            if "Did not find any .jsonl files" not in msg:
                raise

            # O‘quv va sinov vektorlari yaratilgan bo‘lsa, davom etamiz.
            if self._has_vectorized(data_dir):
                self.stdout.write(self.style.WARNING(
                    f"{title}: challenge bo‘limi topilmadi, ammo o‘quv va sinov vektorlari tayyor — davom etilmoqda."
                ))
                return

            # O‘quv va sinov vektorlari ham yaratilmagan bo‘lsa, boshqa xatolik yuz bergan.
            raise

    def handle(self, *args, **opts):
        import thrember

        label_type = opts["label_type"]
        self._safe_vectorize(thrember, opts["apk_dir"], label_type, "APK")
        self._safe_vectorize(thrember, opts["pdf_dir"], label_type, "PDF")
        self.stdout.write(self.style.SUCCESS("Vektorlash yakunlandi."))
