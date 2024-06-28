from abc import abstractmethod


class GenericParser:
    def __init__(self, name):
        self.name = name

    @abstractmethod
    def can_handle(self, file):
        raise NotImplementedError("this method should be implemented by every parser")

    @abstractmethod
    def process(self, file):
        raise NotImplementedError("this method should be implemented by every parser")
