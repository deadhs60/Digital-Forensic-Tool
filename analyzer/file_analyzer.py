import os

def analyze_file(file_path):
    info = {}
    
    info['File Name'] = os.path.basename(file_path)
    info['File Type'] = file_path.split('.')[-1]

    return info