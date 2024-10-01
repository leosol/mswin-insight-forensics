

class PendingFiles:
    def __init__(self):
        self.pending_files = []

    def append_pending_file(self, file_path):
        self.pending_files.append(file_path)

    def get_pending_files(self):
        return self.pending_files

    def clear_pending_files(self):
        self.pending_files = []