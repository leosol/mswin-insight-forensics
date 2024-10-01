from abc import abstractmethod
from mswinif.PendingFiles import PendingFiles


class GenericParser:
    def __init__(self, name):
        self.name = name
        self.tmp_dir = None
        self.output_dir = None
        self.input_dir = None
        self.tools_dir = None

    def configure(self, tmp_dir, output_dir, input_dir, tools_dir, pending_files: PendingFiles):
        self.tmp_dir = tmp_dir
        self.output_dir = output_dir
        self.input_dir = input_dir
        self.tools_dir = tools_dir
        self.pending_files = pending_files

    @abstractmethod
    def can_handle(self, file):
        raise NotImplementedError("this method should be implemented by every parser")

    @abstractmethod
    def process(self, file):
        raise NotImplementedError("this method should be implemented by every parser")
