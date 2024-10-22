import logging
from mswinif.parsers.GenericParser import GenericParser
from mswinif import fs_utils
import pyscca


class WindowsPrefetchParser(GenericParser):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__(name="prefetch_events")
        self.system_hive_pointer = None

    def get_timestamp_property_names(self):
        return ["executed_at"]

    def can_handle(self, file):
        file_ext = fs_utils.get_file_extension(file).strip().lower()
        if file_ext == '.pf':
            return True
        return False

    def process(self, file):
        collected_records = []
        try:
            scca = pyscca.open(file)
        except:
            self.logger.warning(f"Prefetch parser error: Can't process file {file}.")
            return collected_records
        executable_name = scca.executable_filename
        run_count = scca.run_count
        pf_hash = scca.prefetch_hash
        for x in range(run_count):
            try:
                run_time_str = (scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S.%f"))
                collected_records.append({
                    "executable_name": executable_name,
                    "run_count": run_count,
                    "pf_hash": pf_hash,
                    "executed_at": run_time_str
                })
            except:
                pass
        return collected_records

def main():
    pf_parser = WindowsPrefetchParser()
    pf_parser.process("I:\\INVASAO\\M26630-2024-invasao-bancario2\\prefetch\\ACROBAT.EXE-F94F9B2A.pf")


if __name__ == "__main__":
    main()