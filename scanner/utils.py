import hashlib
import os


def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

# import thrember
#
#
# # where you want to store datasets
# apk_dir = os.getenv("APK_DIR")
# pdf_dir = os.getenv("PDF_DIR")
#
# # APK
# thrember.download_dataset(apk_dir, file_type="APK", split="train")
# thrember.download_dataset(apk_dir, file_type="APK", split="test")
#
# # PDF
# thrember.download_dataset(pdf_dir, file_type="PDF", split="train")
# thrember.download_dataset(pdf_dir, file_type="PDF", split="test")
#
# print("Done.")
