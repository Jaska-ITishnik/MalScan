import json
from pathlib import Path

from django.core.management.base import BaseCommand
from django.conf import settings

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score

class Command(BaseCommand):
    help = "Vektorlangan EMBER2024 belgilarida APK va PDF modellarini o‘qitadi."

    def add_arguments(self, parser):
        parser.add_argument("--apk_dir", required=True)
        parser.add_argument("--pdf_dir", required=True)
        parser.add_argument("--max_iter", type=int, default=2000)

    def _train_one(self, name: str, data_dir: str, out_path: Path, max_iter: int):
        import thrember
        X_train, y_train = thrember.read_vectorized_features(data_dir, subset="train")
        X_test, y_test = thrember.read_vectorized_features(data_dir, subset="test")

        m_tr = y_train != -1
        m_te = y_test != -1
        X_train, y_train = X_train[m_tr], y_train[m_tr]
        X_test, y_test = X_test[m_te], y_test[m_te]

        clf = LogisticRegression(
            max_iter=max_iter,
            n_jobs=-1,
            class_weight="balanced",
            solver="saga",
        )
        clf.fit(X_train, y_train)

        proba = clf.predict_proba(X_test)[:, 1]
        pred = (proba >= 0.5).astype(int)

        self.stdout.write(self.style.SUCCESS(f"\n{name} modeli baholash natijalari:"))
        self.stdout.write(classification_report(y_test, pred, digits=4))
        try:
            auc = roc_auc_score(y_test, proba)
            self.stdout.write(self.style.SUCCESS(f"ROC-AUC ko‘rsatkichi: {auc:.4f}"))
        except Exception:
            pass

        out_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, out_path)
        self.stdout.write(self.style.SUCCESS(f"Saqlandi: {out_path}"))

        return {
            "name": name,
            "model": "LogisticRegression(saga)",
            "dim": int(X_train.shape[1]),
            "train_rows": int(X_train.shape[0]),
            "test_rows": int(X_test.shape[0]),
        }

    def handle(self, *args, **opts):
        settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

        meta = {
            "version": "v1",
            "notes": [
                "EMBER2024 vektorlangan belgilarida o‘qitilgan.",
                "Ishlash vaqtida thrember.features.PEFeatureExtractor.feature_vector(bytes) ishlatiladi.",
                "Hozirgi tahlil yo‘li faqat APK va PDF formatlarini qo‘llaydi.",
            ],
            "models": {},
        }

        meta["models"]["apk"] = self._train_one("APK", opts["apk_dir"], settings.APK_MODEL_PATH, opts["max_iter"])
        meta["models"]["pdf"] = self._train_one("PDF", opts["pdf_dir"], settings.PDF_MODEL_PATH, opts["max_iter"])

        settings.MODEL_META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Model ma’lumotlari saqlandi: {settings.MODEL_META_PATH}"))
