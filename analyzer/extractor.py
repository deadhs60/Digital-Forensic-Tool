import re

def extract_strings(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    # Extract readable ASCII strings
    strings = re.findall(rb"[ -~]{6,}", data)

    # Convert bytes to string
    return [s.decode("utf-8", errors="ignore") for s in strings]