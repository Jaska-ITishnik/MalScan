from __future__ import annotations

import copy
import re


_LEGACY_TITLES = {
    "Ссылки в документе": "Hujjatdagi havolalar",
    "IP-адреса": "IP manzillar",
    "JavaScript в PDF": "PDF ichida JavaScript",
    "Автодействия (OpenAction/AA)": "Avtomatik amallar (OpenAction/AA)",
    "Launch Action": "Tashqi amalni ishga tushirish",
    "Встроенные файлы": "Ichiga biriktirilgan fayllar",
    "Высокая энтропия": "Yuqori entropiya",
    "Нет Android manifest": "Android manifest topilmadi",
    "Зашифрованное содержимое APK": "APK ichidagi ma’lumotlar shifrlangan",
    "Android manifest и пакет": "Android manifest va paket",
    "Android manifest найден": "Android manifest topildi",
    "Версия приложения": "Ilova versiyasi",
    "Минимальная версия Android": "Androidning eng eski qo‘llanadigan versiyasi",
    "Нативные библиотеки": "Mahalliy kutubxonalar",
    "Запрошенные Android-разрешения": "So‘ralgan Android ruxsatlari",
    "Android-разрешения": "Android ruxsatlari",
    "Снаружи доступные компоненты": "Tashqi ilovalarga ochiq komponentlar",
    "Компоненты приложения": "Ilova komponentlari",
    "Слишком большой manifest": "Manifest hajmi katta",
    "Структура APK": "APK tuzilmasi",
    "DEX-код не найден": "DEX kodi topilmadi",
    "Сетевые адреса в приложении": "Ilovadagi tarmoq manzillari",
    "Динамическая загрузка кода": "Kodni dinamik yuklash",
    "Запуск системных команд": "Tizim buyruqlarini ishga tushirish",
    "Доступность / перехват ввода": "Maxsus imkoniyatlar xizmati",
    "Ошибка чтения APK": "APK faylini o‘qib bo‘lmadi",
}

_LEGACY_CATEGORIES = {
    "Сеть": "Tarmoq",
    "Скрипты": "Skriptlar",
    "Вложения": "Biriktirmalar",
    "Обфускация": "Yashirish",
    "Структура": "Tuzilma",
    "Поведение": "Xatti-harakat",
    "Разрешения": "Ruxsatlar",
    "Компоненты": "Komponentlar",
    "Сеть и код": "Tarmoq va kod",
}


def localize_saved_scan(scan) -> None:
    """Translate Russian summaries saved by earlier versions for display only."""
    reasons_json = copy.deepcopy(scan.reasons_json or {})
    if reasons_json.get("error", "").startswith("Model is missing:"):
        reasons_json["error"] = "Tahlil modeli topilmadi. Kerakli model artifacts/ papkasida mavjudligini tekshiring."
    elif reasons_json.get("error", "").startswith("Unsupported file type"):
        reasons_json["error"] = "Bu fayl turi qo‘llab-quvvatlanmaydi."
    elif reasons_json.get("error", "").startswith("Model must support"):
        reasons_json["error"] = "Model kerakli tahlil usullarini qo‘llamaydi."

    summary = reasons_json.get("user_summary")
    if not isinstance(summary, dict):
        scan.reasons_json = reasons_json
        return

    for category in summary.get("categories", []):
        if isinstance(category, dict):
            category["name"] = _LEGACY_CATEGORIES.get(category.get("name"), category.get("name"))

    for reason in summary.get("reasons", []):
        if not isinstance(reason, dict):
            continue
        title = reason.get("title", "")
        detail = reason.get("detail", "")
        reason["title"] = _LEGACY_TITLES.get(title, title)
        reason["detail"] = _localize_detail(title, detail)

    scan.reasons_json = reasons_json


def _localize_detail(title: str, detail: str) -> str:
    match = re.fullmatch(r"Найдено URL: (\d+)", detail)
    if match:
        return f"Topilgan URL manzillari: {match.group(1)} ta"

    match = re.fullmatch(r"Найдено IP: (\d+)", detail)
    if match:
        return f"Topilgan IP manzillar: {match.group(1)} ta"

    details = {
        "JavaScript в PDF": "JavaScript belgilariga mos yozuvlar topildi.",
        "Автодействия (OpenAction/AA)": "Fayl ochilganda bajariladigan amallar topildi.",
        "Launch Action": "Tashqi buyruq yoki amalni ishga tushirish belgisi topildi.",
        "Встроенные файлы": "PDF ichida qo‘shimcha fayl biriktirilgan bo‘lishi mumkin.",
        "Нет Android manifest": "APK ichida AndroidManifest.xml yo‘q; fayl odatiy Android ilova paketiga o‘xshamaydi.",
        "Android manifest и пакет": "Paket nomi: " + detail.partition(": ")[2],
        "Android manifest найден": "AndroidManifest.xml mavjud, lekin paket nomini o‘qib bo‘lmadi.",
        "Версия приложения": "Ilova versiyasi: " + detail,
        "Минимальная версия Android": "Androidning eng eski qo‘llanadigan versiyasi: " + detail,
        "Запрошенные Android-разрешения": detail.replace("Найдено разрешений:", "Jami ruxsatlar:").replace("чувствительных из проверяемого списка нет.", "tekshirilgan sezgir ruxsatlar topilmadi."),
        "Android-разрешения": "Manifestda so‘ralgan ruxsatlar ro‘yxati topilmadi.",
        "Снаружи доступные компоненты": re.sub(
            r"^(\d+) компонент открыт другим приложениям без указанного permission: (.*)\.$",
            r"\1 ta komponent boshqa ilovalarga ruxsatsiz ochiq: \2.",
            detail,
        ),
        "Компоненты приложения": re.sub(
            r"^В manifest описано компонентов: (\d+); открытых без permission не найдено\.$",
            r"Manifestda \1 ta komponent bor; ruxsatsiz ochiq komponent topilmadi.",
            detail,
        ),
        "Слишком большой manifest": "AndroidManifest.xml 2 MB dan katta bo‘lgani uchun tahlil qilinmadi.",
        "DEX-код не найден": "APK ichida classes.dex yo‘q; fayl to‘liq APK ekanini tekshiring.",
        "Динамическая загрузка кода": "Kodni dinamik yuklashga oid belgilar topildi. Kontekstni tekshirish lozim.",
        "Запуск системных команд": "Tizim buyruqlarini ishga tushirishga oid belgilar topildi. Kontekstni tekshirish lozim.",
        "Доступность / перехват ввода": "Maxsus imkoniyatlar xizmati yoki kiritishni kuzatishga oid belgilar topildi.",
        "Структура APK": detail.replace("ZIP-записей:", "ZIP yozuvlari:").replace("DEX-файлов:", "DEX fayllari:"),
        "Ошибка чтения APK": "Fayl buzilgan yoki qo‘llab-quvvatlanmaydigan formatda bo‘lishi mumkin.",
    }
    if title in details:
        return details[title]

    if title == "Высокая энтропия":
        match = re.match(r"([\d.]+)", detail)
        if match:
            return f"{match.group(1)} (ma’lumotlar qadoqlangan yoki shifrlangan bo‘lishi mumkin)"
    if title == "Зашифрованное содержимое APK":
        count = re.search(r"файлов: (\d+)", detail)
        critical = re.search(r"ключевые файлы: ([^.]+)", detail)
        result = f"APK ichidagi {count.group(1) if count else 'bir nechta'} ta ZIP yozuvi shifrlangan."
        if critical:
            result += f" Shifrlangan muhim fayllar: {critical.group(1)}."
        return result + " Shu sabab ruxsatlar, komponentlar va kodni tahlil qilib bo‘lmadi."
    if title == "Нативные библиотеки" and detail.startswith("Найдено .so файлов:"):
        return re.sub(r"^Найдено \.so файлов: (\d+)", r".so fayllari: \1 ta", detail).replace(
            "Наличие native-кода само по себе не означает вредоносность.",
            "Bunday kod borligi o‘z-o‘zidan zararli ekanini bildirmaydi.",
        )
    if title == "Нативные библиотеки":
        return "APK ichida .so formatidagi mahalliy kod kutubxonalari mavjud."
    if title == "Сетевые адреса в приложении":
        match = re.search(r"URL: (\d+), IP-адресов: (\d+)", detail)
        if match:
            return f"Kod yoki manifestdagi URL manzillar: {match.group(1)} ta, IP manzillar: {match.group(2)} ta. Bu manzillar odatiy ilova vazifalari uchun ham ishlatilishi mumkin."
    return detail
