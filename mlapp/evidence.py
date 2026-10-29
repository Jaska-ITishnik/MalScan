from __future__ import annotations

import math
import re
import struct
import zipfile
from xml.etree import ElementTree

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
    categories = {"Tarmoq": 0, "Skriptlar": 0, "Biriktirmalar": 0, "Yashirish": 0}

    if urls:
        reasons.append({"title": "Hujjatdagi havolalar", "detail": f"Topilgan URL manzillari: {len(urls)}", "severity": "high"})
        categories["Tarmoq"] += 35
    if ips:
        reasons.append({"title": "IP manzillar", "detail": f"Topilgan IP manzillar: {len(ips)}", "severity": "medium"})
        categories["Tarmoq"] += 15

    if hits["javascript"] > 0:
        reasons.append({"title": "PDF ichida JavaScript", "detail": "JavaScript belgilariga mos yozuvlar topildi.", "severity": "high"})
        categories["Skriptlar"] += 40
    if hits["open_action"] > 0:
        reasons.append({"title": "Avtomatik amallar (OpenAction/AA)", "detail": "Fayl ochilganda ishga tushadigan amallar topildi.", "severity": "high"})
        categories["Skriptlar"] += 25
    if hits["launch"] > 0:
        reasons.append({"title": "Tashqi amalni ishga tushirish", "detail": "Tashqi buyruq yoki amalni ishga tushirish belgisi topildi.", "severity": "high"})
        categories["Skriptlar"] += 40

    if hits["embedded"] > 0:
        reasons.append({"title": "Ichiga biriktirilgan fayllar", "detail": "PDF ichida qo‘shimcha fayl biriktirilgan bo‘lishi mumkin.", "severity": "high"})
        categories["Biriktirmalar"] += 35

    if ent >= 7.2:
        reasons.append(
            {"title": "Yuqori entropiya", "detail": f"{ent:.2f} (ma’lumotlar qadoqlangan yoki shifrlangan bo‘lishi mumkin)", "severity": "medium"})
        categories["Yashirish"] += 25

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
    categories = {"Tuzilma": 0, "Ruxsatlar": 0, "Komponentlar": 0, "Tarmoq va kod": 0}
    evidence = {
        "archive_entries": 0,
        "dex_files": 0,
        "native_libraries": 0,
        "permissions": [],
        "exported_components": 0,
        "urls": [],
        "encrypted_entries": 0,
        "encrypted_entry_names": [],
        "package": "",
        "version": "",
        "min_sdk": "",
    }

    def add_reason(title: str, detail: str, severity: str = "low", category: str = "Tuzilma", weight: int = 8):
        reasons.append({"title": title, "detail": detail, "severity": severity})
        categories[category] += weight

    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            infos = archive.infolist()
            names = [entry.filename for entry in infos]
            name_set = set(names)
            dex_names = [name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", name)]
            native_names = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
            evidence["archive_entries"] = len(infos)
            evidence["dex_files"] = len(dex_names)
            evidence["native_libraries"] = len(native_names)
            encrypted_names = [entry.filename for entry in infos if entry.flag_bits & 0x1]
            encrypted_name_set = set(encrypted_names)
            evidence["encrypted_entries"] = len(encrypted_names)
            evidence["encrypted_entry_names"] = encrypted_names[:10]

            if "AndroidManifest.xml" not in name_set:
                add_reason("Android manifest topilmadi", "APK ichida AndroidManifest.xml yo‘q; fayl odatiy Android ilova paketiga o‘xshamaydi.", "high", weight=35)
            elif "AndroidManifest.xml" in encrypted_name_set:
                encrypted_critical = [
                    name for name in encrypted_names
                    if name == "AndroidManifest.xml" or re.fullmatch(r"classes(?:\d+)?\.dex", name)
                ]
                critical_detail = f" Shifrlangan muhim fayllar: {', '.join(encrypted_critical[:4])}." if encrypted_critical else ""
                add_reason(
                    "APK ichidagi ma’lumotlar shifrlangan",
                    f"APK ichidagi {len(encrypted_names)} ta ZIP yozuvi shifrlangan.{critical_detail} Shu sabab ruxsatlar, komponentlar va kodni tahlil qilib bo‘lmadi.",
                    "high",
                    "Tuzilma",
                    35,
                )
            else:
                manifest_info = archive.getinfo("AndroidManifest.xml")
                if manifest_info.file_size <= 2 * 1024 * 1024:
                    manifest = archive.read("AndroidManifest.xml")
                    manifest_data = _parse_apk_manifest(manifest)
                    evidence.update({key: manifest_data[key] for key in ("package", "version", "min_sdk", "permissions")})
                    if evidence["package"]:
                        add_reason("Android manifest va paket", "Paket nomi: {}".format(evidence["package"]), "low", weight=5)
                    else:
                        add_reason("Android manifest topildi", "AndroidManifest.xml mavjud, lekin paket nomini o‘qib bo‘lmadi.", "low", weight=5)
                    if evidence["version"]:
                        add_reason("Ilova versiyasi", evidence["version"], "low", weight=2)
                    if evidence["min_sdk"]:
                        add_reason("Androidning eng eski qo‘llanadigan versiyasi", evidence["min_sdk"], "low", weight=2)

                    risky_permissions = {
                        "SMS va qo‘ng‘iroqlar": {
                            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
                            "android.permission.RECEIVE_MMS", "android.permission.READ_CALL_LOG",
                            "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
                        },
                        "Kontaktlar va telefon": {
                            "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                            "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
                        },
                        "Joylashuv va mikrofon": {
                            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
                            "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
                        },
                        "Fayllar va ilova o‘rnatish": {
                            "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE",
                            "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.REQUEST_INSTALL_PACKAGES",
                        },
                        "Boshqa oynalar ustida ko‘rsatish": {
                            "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE",
                            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                        },
                    }
                    found_permissions = set(evidence["permissions"])
                    for group, known_permissions in risky_permissions.items():
                        found = sorted(found_permissions & known_permissions)
                        if found:
                            short_names = [permission.rsplit(".", 1)[-1] for permission in found[:3]]
                            extra = f" va yana {len(found) - 3} ta" if len(found) > 3 else ""
                            severity = "high" if group == "SMS va qo‘ng‘iroqlar" else "medium"
                            add_reason(
                                f"Ruxsatlar: {group}",
                                f"{len(found)} ta ruxsat: {', '.join(short_names)}{extra}. Ruxsatning o‘zi zararli xatti-harakatni isbotlamaydi.",
                                severity,
                                "Ruxsatlar",
                                24 if severity == "high" else 14,
                            )
                    if evidence["permissions"] and categories["Ruxsatlar"] == 0:
                        add_reason("So‘ralgan Android ruxsatlari", f"Jami ruxsatlar: {len(evidence['permissions'])}; tekshirilgan sezgir ruxsatlar topilmadi.", "low", "Ruxsatlar", 4)
                    elif not evidence["permissions"]:
                        add_reason("Android ruxsatlari", "Manifestda so‘ralgan ruxsatlar ro‘yxati topilmadi.", "low", "Ruxsatlar", 3)

                    components = manifest_data.get("components", [])
                    open_components = [component for component in components if component.get("exported") is True and not component.get("permission")]
                    evidence["exported_components"] = len(open_components)
                    if open_components:
                        examples = ", ".join(component["name"] for component in open_components[:3])
                        add_reason(
                            "Tashqi ilovalarga ochiq komponentlar",
                            f"{len(open_components)} ta komponent boshqa ilovalarga ruxsatsiz ochiq: {examples}.",
                            "medium",
                            "Komponentlar",
                            18,
                        )
                    elif components:
                        add_reason("Ilova komponentlari", f"Manifestda {len(components)} ta komponent bor; ruxsatsiz ochiq komponent topilmadi.", "low", "Komponentlar", 5)
                else:
                    add_reason("Manifest hajmi katta", "AndroidManifest.xml 2 MB dan katta bo‘lgani uchun tahlil qilinmadi.", "medium", weight=12)

            add_reason("APK tuzilmasi", f"ZIP yozuvlari: {len(infos)}; DEX fayllari: {len(dex_names)}.", "low", weight=6)
            if not dex_names:
                add_reason("DEX kodi topilmadi", "APK ichida classes.dex yo‘q; fayl to‘liq APK ekanini tekshiring.", "medium", weight=12)
            if native_names:
                add_reason("Mahalliy kutubxonalar", f".so fayllari: {len(native_names)} ta ({', '.join(native_names[:3])}). Bunday kod borligi o‘z-o‘zidan zararli ekanini bildirmaydi.", "medium", "Tarmoq va kod", 12)

            # Inspect the manifest and DEX string tables without extracting files to disk.
            searchable = bytearray()
            for name in ["AndroidManifest.xml", *dex_names[:8]]:
                try:
                    info = archive.getinfo(name)
                    if info.flag_bits & 0x1:
                        continue
                    if info.file_size <= 16 * 1024 * 1024:
                        searchable.extend(archive.read(name))
                except (KeyError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                    continue
            searchable = bytes(searchable)
            urls = list(dict.fromkeys(match.decode("ascii", "ignore").rstrip(".,;)") for match in URL_RE.findall(searchable)))
            ips = list(dict.fromkeys(match.decode("ascii", "ignore") for match in IP_RE.findall(searchable)))
            evidence["urls"] = urls[:10]
            evidence["ip_count"] = len(ips)
            if urls or ips:
                detail = f"Kod yoki manifestdagi URL manzillar: {len(urls)} ta, IP manzillar: {len(ips)} ta"
                if urls:
                    detail += f"; misollar: {', '.join(urls[:3])}"
                add_reason("Ilovadagi tarmoq manzillari", detail + ". Bu manzillar odatiy ilova vazifalari uchun ham ishlatilishi mumkin.", "medium", "Tarmoq va kod", 12)

            indicator_patterns = {
                "Kodni dinamik yuklash": (rb"DexClassLoader", rb"PathClassLoader", rb"InMemoryDexClassLoader"),
                "Tizim buyruqlarini ishga tushirish": (rb"Runtime;->exec", rb"java/lang/ProcessBuilder", rb"/system/bin/sh"),
                "Maxsus imkoniyatlar xizmati": (rb"AccessibilityService", rb"BIND_ACCESSIBILITY_SERVICE", rb"getWindowState"),
            }
            for title, patterns in indicator_patterns.items():
                hits = sum(searchable.count(pattern.lower()) + searchable.count(pattern) for pattern in patterns)
                if hits:
                    add_reason(title, f"Manifest yoki DEX ichida shu belgiga oid yozuvlar topildi ({hits} ta). Bu yozuvning o‘zi funksiya ishlatilishini isbotlamaydi; kontekstni tekshirish kerak.", "medium", "Tarmoq va kod", 12)

    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        add_reason(
            "APK faylini o‘qib bo‘lmadi",
            "Fayl buzilgan yoki qo‘llab-quvvatlanmaydigan formatda bo‘lishi mumkin.",
            "high",
            weight=35,
        )

    total = sum(categories.values()) or 1
    cat_list = [{"name": name, "score": int(round(value * 100 / total))} for name, value in categories.items() if value > 0]
    return {"reasons": reasons[:10], "categories": cat_list, "evidence": evidence}


def _parse_apk_manifest(data: bytes) -> dict:
    """Read the small set of Android manifest fields needed for a user-facing summary."""
    android_ns = "{http://schemas.android.com/apk/res/android}"
    result = {"package": "", "version": "", "min_sdk": "", "permissions": [], "components": []}

    if data.lstrip().startswith(b"<"):
        try:
            root = ElementTree.fromstring(data)
            result["package"] = root.attrib.get("package", "")
            version_code = root.attrib.get(android_ns + "versionCode", "")
            version_name = root.attrib.get(android_ns + "versionName", "")
            result["version"] = version_name or version_code
            for node in root.iter():
                tag = node.tag.rsplit("}", 1)[-1]
                if tag.startswith("uses-permission"):
                    permission = node.attrib.get(android_ns + "name")
                    if permission:
                        result["permissions"].append(permission)
                if tag in {"activity", "activity-alias", "service", "receiver", "provider"}:
                    result["components"].append({
                        "name": node.attrib.get(android_ns + "name", tag),
                        "exported": node.attrib.get(android_ns + "exported", "").lower() == "true",
                        "permission": node.attrib.get(android_ns + "permission", ""),
                    })
                if tag == "uses-sdk":
                    result["min_sdk"] = node.attrib.get(android_ns + "minSdkVersion", "")
            result["permissions"] = sorted(set(result["permissions"]))
            return result
        except ElementTree.ParseError:
            return result

    # Android's compiled binary XML uses a string pool followed by start-element chunks.
    strings = []
    offset = 0

    def read_length8(blob: bytes, pos: int) -> tuple[int, int]:
        first = blob[pos]
        if first & 0x80:
            return (((first & 0x7F) << 8) | blob[pos + 1]), pos + 2
        return first, pos + 1

    def read_length16(blob: bytes, pos: int) -> tuple[int, int]:
        first = struct.unpack_from("<H", blob, pos)[0]
        if first & 0x8000:
            second = struct.unpack_from("<H", blob, pos + 2)[0]
            return (((first & 0x7FFF) << 16) | second), pos + 4
        return first, pos + 2

    try:
        while offset + 8 <= len(data):
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
            if chunk_size < header_size or offset + chunk_size > len(data):
                break
            if offset == 0 and chunk_type == 0x0003:  # XML container; child chunks follow its header.
                offset += header_size
                continue
            if chunk_type == 0x0001 and header_size >= 28:  # string pool
                string_count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
                string_offsets = struct.unpack_from(f"<{string_count}I", data, offset + header_size) if string_count else ()
                utf8 = bool(flags & 0x100)
                for string_offset in string_offsets:
                    pos = offset + strings_start + string_offset
                    if utf8:
                        _, pos = read_length8(data, pos)
                        byte_length, pos = read_length8(data, pos)
                        strings.append(data[pos:pos + byte_length].decode("utf-8", "replace"))
                    else:
                        char_length, pos = read_length16(data, pos)
                        strings.append(data[pos:pos + char_length * 2].decode("utf-16le", "replace"))
            elif chunk_type == 0x0102 and strings:  # start element
                ext = offset + 16
                name_index = struct.unpack_from("<I", data, ext + 4)[0]
                attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", data, ext + 8)
                if name_index >= len(strings) or attribute_size < 20:
                    offset += chunk_size
                    continue
                tag = strings[name_index]
                attrs = {}
                attr_offset = ext + attribute_start
                for index in range(attribute_count):
                    pos = attr_offset + index * attribute_size
                    if pos + 20 > offset + chunk_size:
                        break
                    _, attr_name, raw_value = struct.unpack_from("<III", data, pos)
                    value_type = data[pos + 15]
                    value_data = struct.unpack_from("<I", data, pos + 16)[0]
                    key = strings[attr_name] if attr_name < len(strings) else ""
                    if raw_value != 0xFFFFFFFF and raw_value < len(strings):
                        value = strings[raw_value]
                    elif value_type == 0x03 and value_data < len(strings):
                        value = strings[value_data]
                    elif value_type == 0x12:
                        value = "true" if value_data else "false"
                    elif value_type in (0x10, 0x11):
                        value = str(value_data)
                    else:
                        value = ""
                    attrs[key] = value

                if tag == "manifest":
                    result["package"] = attrs.get("package", "")
                    result["version"] = attrs.get("versionName") or attrs.get("versionCode", "")
                elif tag.startswith("uses-permission") and attrs.get("name"):
                    result["permissions"].append(attrs["name"])
                elif tag == "uses-sdk":
                    result["min_sdk"] = attrs.get("minSdkVersion", "")
                elif tag in {"activity", "activity-alias", "service", "receiver", "provider"}:
                    result["components"].append({
                        "name": attrs.get("name", tag),
                        "exported": attrs.get("exported", "").lower() == "true",
                        "permission": attrs.get("permission", ""),
                    })
            offset += chunk_size
    except (IndexError, struct.error, UnicodeError):
        return result

    result["permissions"] = sorted(set(result["permissions"]))
    return result
