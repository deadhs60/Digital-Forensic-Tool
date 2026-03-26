import hashlib

def calculate_hash(file_path):
    hashes = {}
    with open(file_path, "rb") as f:
        data = f.read()
        hashes["MD5"] = hashlib.md5(data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    return hashes