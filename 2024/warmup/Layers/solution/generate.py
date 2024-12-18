import os
import random
from datetime import datetime, timedelta
import zipfile

TARGET_STRING = "SU5USUdSSVRJezdoM3IzNV9sNHkzcjVfNzBfN2gxNV9jaDRsbDNuNjN9"
NUM_FILES = len(TARGET_STRING)
ARCHIVE_NAME = "layers.zip"

if not os.path.exists("files"):
    os.mkdir("files")

file_names = [f"{i}" for i in range(NUM_FILES)]
random.shuffle(file_names)

base_time = datetime.now()

for i, char in enumerate(TARGET_STRING):
    filename = file_names[i]
    file_path = os.path.join("files", filename)
    with open(file_path, "w") as f:
        binary_char = format(ord(char), '08b')
        f.write(binary_char)
    mod_time = (base_time + timedelta(seconds=i * 30)).timestamp()
    os.utime(file_path, (mod_time, mod_time))

sorted_files_by_time = sorted(os.listdir(
    "files"), key=lambda f: os.path.getmtime(os.path.join("files", f)))

with zipfile.ZipFile(ARCHIVE_NAME, 'w') as zipf:
    for root, dirs, files in os.walk("files"):
        for file in files:
            zipf.write(os.path.join(root, file), file)

for file_name in os.listdir("files"):
    os.remove(os.path.join("files", file_name))
os.rmdir("files")

print(f"Challenge created: {ARCHIVE_NAME}")
