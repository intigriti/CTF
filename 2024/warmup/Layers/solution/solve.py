import zipfile
import os
from datetime import datetime

ARCHIVE_NAME = "layers.zip"
EXTRACT_DIR = "files"


def binary_to_char(binary_str):
    return chr(int(binary_str, 2))


with zipfile.ZipFile(ARCHIVE_NAME, 'r') as zipf:
    for info in zipf.infolist():
        extracted_path = zipf.extract(info, EXTRACT_DIR)
        date_time = datetime(*info.date_time)
        mod_time = date_time.timestamp()
        os.utime(extracted_path, (mod_time, mod_time))

file_data = []
for file_name in os.listdir(EXTRACT_DIR):
    file_path = os.path.join(EXTRACT_DIR, file_name)
    mod_time = os.path.getmtime(file_path)
    with open(file_path, "r") as f:
        binary_data = f.read().strip()
        char = binary_to_char(binary_data)
    file_data.append((mod_time, char))

file_data.sort()
reconstructed_string = ''.join([char for _, char in file_data])

print("Reconstructed String:")
print(reconstructed_string)

for file_name in os.listdir(EXTRACT_DIR):
    os.remove(os.path.join(EXTRACT_DIR, file_name))
os.rmdir(EXTRACT_DIR)
