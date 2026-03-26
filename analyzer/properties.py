from datetime import datetime
import os

def file_properties(file_path):
    stat = os.stat(file_path)
    return {
        "File Size (KB)": round(stat.st_size / 1024, 2),
        "Created Time": str(datetime.fromtimestamp(stat.st_ctime)),
        "Modified Time": str(datetime.fromtimestamp(stat.st_mtime))
    }