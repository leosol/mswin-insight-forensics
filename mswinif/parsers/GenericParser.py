from abc import abstractmethod
from mswinif.PendingFiles import PendingFiles
from datetime import datetime
import pytz
from tzlocal import get_localzone

def convert_utc_to_local(date_string):
    try:
        utc_time = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=pytz.UTC)
        local_timezone = get_localzone()
        local_time = utc_time.astimezone(local_timezone)
        return local_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    except:
        return None


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

    def get_timestamp_property_names(self):
        return []

    @abstractmethod
    def can_handle(self, file):
        raise NotImplementedError("this method should be implemented by every parser")

    @abstractmethod
    def process(self, file):
        raise NotImplementedError("this method should be implemented by every parser")

    def post_process(self, collected_data):
        if len(self.get_timestamp_property_names()) > 0:
            for item in collected_data:
                for key in self.get_timestamp_property_names():
                    if key in item:
                        new_key = f"{key}_local_tz"
                        new_value = convert_utc_to_local(item[key])
                        item[new_key] = new_value

