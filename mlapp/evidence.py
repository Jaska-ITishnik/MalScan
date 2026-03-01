from __future__ import annotations

import math
import re
import zipfile

URL_RE = re.compile(rb"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

PDF_MARKERS = {
    "javascript": [rb"/JavaScript", rb"/JS"],
    "open_action": [rb"/OpenAction", rb"/AA"],
    "launch": [rb"/Launch"],
    "embedded": [rb"/EmbeddedFile", rb"/Filespec"],
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def explain_pdf(file_bytes: bytes) -> dict:
    b = file_bytes
    low = b.lower()

    urls = URL_RE.findall(low)
    ips = IP_RE.findall(low)

    hits = {}
    for k, markers in PDF_MARKERS.items():
        hits[k] = sum(low.count(m.lower()) for m in markers)

    ent = shannon_entropy(b)

    reasons = []
    categories = {"Сеть": 0, "Скрипты": 0, "Вложения": 0, "Обфускация": 0}

    if urls:
        reasons.append({"title": "Ссылки в документе", "detail": f"Найдено URL: {len(urls)}", "severity": "high"})
        categories["Сеть"] += 35
    if ips:
        reasons.append({"title": "IP-адреса", "detail": f"Найдено IP: {len(ips)}", "severity": "medium"})
        categories["Сеть"] += 15

    if hits["javascript"] > 0:
        reasons.append({"title": "JavaScript в PDF", "detail": "Обнаружены JS-маркеры", "severity": "high"})
        categories["Скрипты"] += 40
    if hits["open_action"] > 0:
        reasons.append({"title": "Автодействия (OpenAction/AA)", "detail": "Действия при открытии", "severity": "high"})
        categories["Скрипты"] += 25
    if hits["launch"] > 0:
        reasons.append({"title": "Launch Action", "detail": "Признаки запуска внешних действий", "severity": "high"})
        categories["Скрипты"] += 40

    if hits["embedded"] > 0:
        reasons.append({"title": "Встроенные файлы", "detail": "Есть EmbeddedFile/Filespec", "severity": "high"})
        categories["Вложения"] += 35

    if ent >= 7.2:
        reasons.append(
            {"title": "Высокая энтропия", "detail": f"{ent:.2f} (возможна упаковка/шифрование)", "severity": "medium"})
        categories["Обфускация"] += 25

    total = sum(categories.values()) or 1
    cat_list = [{"name": k, "score": int(round(v * 100 / total))} for k, v in categories.items() if v > 0]

    return {
        "reasons": reasons[:8],
        "categories": cat_list,
        "evidence": {
            "url_count": len(urls),
            "ip_count": len(ips),
            "entropy": ent,
            "marker_hits": hits,
        },
    }


def explain_apk_light(apk_path: str) -> dict:
    reasons = []
    categories = {"Структура": 0, "Поведение": 0}

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            has_dex = any(n.endswith(".dex") for n in names)
            has_so = any(n.endswith(".so") for n in names)

            if has_dex:
                categories["Структура"] += 15
            if has_so:
                reasons.append(
                    {"title": "Нативные библиотеки", "detail": "В APK есть .so (native code)", "severity": "medium"})
                categories["Поведение"] += 25

    except Exception:
        reasons.append({"title": "Ошибка чтения APK", "detail": "Не удалось открыть как ZIP", "severity": "high"})

    total = sum(categories.values()) or 1
    cat_list = [{"name": k, "score": int(round(v * 100 / total))} for k, v in categories.items() if v > 0]

    return {"reasons": reasons[:8], "categories": cat_list, "evidence": {}}
