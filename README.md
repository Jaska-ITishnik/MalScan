# MalScan — zararli fayllarni statik tahlil qilish

MalScan APK va PDF fayllarni ishga tushirmasdan tahlil qiladi, ML modeli yordamida xavf darajasini baholaydi va topilgan belgilarni tushuntiradi.

## Talablar

- Python 3.12
- PostgreSQL
- Linux tizimida `libmagic1`

## O‘rnatish

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt-get install -y libmagic1
```

`root/settings.py` PostgreSQL ulanishi uchun `.env` faylidagi `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST` va `DB_PORT` qiymatlarini kutadi. `.env` faylini har bir muhit uchun alohida yarating; u GitHub’ga yuklanmaydi.

## Ma’lumotlar bazasini tayyorlash

```bash
python manage.py migrate
```

## Ishga tushirish

```bash
python manage.py runserver 0.0.0.0:8000
```

Brauzerda `http://127.0.0.1:8000/` manzilini oching.

## Modellarni qayta o‘qitish (ixtiyoriy)

O‘qitish uchun EMBER2024 to‘plamlarini yuklab olib, vektorlash va o‘qitish buyruqlarini bajaring:

```bash
python manage.py ember2024_download --apk_dir data/ember2024_apk --pdf_dir data/ember2024_pdf
python manage.py ember2024_vectorize --apk_dir data/ember2024_apk --pdf_dir data/ember2024_pdf
python manage.py ember2024_train --apk_dir data/ember2024_apk --pdf_dir data/ember2024_pdf
```

O‘qitilgan modellar `artifacts/` papkasiga saqlanadi. Oddiy ishga tushirish uchun ma’lumotlar to‘plamlarini yuklash shart emas.

## Eslatmalar

- Fayllar ishga tushirilmaydi; faqat statik tahlil qilinadi.
- Hozir APK va PDF formatlari tahlil qilinadi.
- Tahlil natijasi ehtimoliy xavfni bildiradi va fayl xavfsizligini mutlaq kafolatlamaydi.
