import csv
import os


class CSVLogger:
    def __init__(self, basedir, filename, remove_existing=False):
        self.basedir = basedir
        self.filename = filename
        self.file_path = os.path.join(basedir, filename)
        if remove_existing and os.path.exists(self.file_path):
            os.remove(self.file_path)
        self.is_open = False
        self.file = None
        self.csv_writer = None

    def open_log(self, header, data=None):
        self.file = open(self.file_path, "a", newline='', encoding='utf-8')
        self.csv_writer = csv.writer(self.file)
        self.csv_writer.writerow(header)
        if data is not None:
            self.csv_writer.writerow(data)
        self.is_open = True
        return data

    def append_log(self, data):
        if not self.is_open:
            raise Exception("File is closed")
        self.csv_writer.writerow(data)
        return data

    def close_log(self):
        if not self.is_open:
            raise Exception("File is closed")
        self.file.flush()
        self.file.close()
        self.is_open = False
