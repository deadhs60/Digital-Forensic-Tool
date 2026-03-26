import exiftool
import json

def get_metadata(file_path):
    try:
        with exiftool.ExifTool() as et:
            result = et.execute("-j", file_path)

        # Convert JSON output to dictionary
        metadata = json.loads(result)[0]

        clean_data = {}
        for key, value in metadata.items():
            clean_data[key] = str(value)

        return clean_data

    except Exception as e:
        return {"Error": str(e)}