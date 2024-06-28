import os
from mswinif.utils import list_files
from mswinif.parsers.winevtx import *
from mswinif.csv_logger.SQLiteDBFastLogger import SQLiteDBFastLogger
from mswinif.csv_logger.Database import Database
from concurrent.futures import ThreadPoolExecutor, as_completed



def print_tasks(tasks:dict):
    for key in tasks:
        cls_name = key.__class__.__name__
        task_name = key.name
        qtd_files = len(tasks[key])
        print(f"Parser {cls_name} has {qtd_files} to process and will save data to {task_name}")


def worker(parser, files, db_fast_logger:SQLiteDBFastLogger):
    cls_name = parser.__class__.__name__
    tbl_name = parser.name
    qtd_items = 0
    header = None
    for file in files:
        collected_items = parser.process(file)
        if len(collected_items) > 0:
            if header is None:
                header = [key for key in collected_items[0]]
                db_fast_logger.add_logger(tbl_name, header)
            for item in collected_items:
                values = [item[key] for key in item]
                db_fast_logger.log_data(tbl_name, values)
        qtd_items = qtd_items + len(collected_items)
    return f"{cls_name} processed {qtd_items} that were saved to {tbl_name}"


class Project:
    def __init__(self, input_dir, output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.parsers = []
        self.parsers.append(KasperskyEndpointParser())
        self.parsers.append(PowerShellParser())
        self.parsers.append(RDPCoreTS())
        self.parsers.append(SecurityParser())
        self.parsers.append(SymantecEndpointProtectionParser())
        self.parsers.append(TSLocalSessionManagerParser())
        self.parsers.append(TSRDPClientParser())
        self.parsers.append(TSRemoteConnectionManagerParser())
        self.parsers.append(WindowsDefenderParser())

    def process(self):
        collected_files = list_files(self.input_dir)
        db_fast_logger = SQLiteDBFastLogger(basedir=self.output_dir)
        tasks = dict()
        for file in collected_files:
            for parser in self.parsers:
                if parser.can_handle(file) or parser.can_handle(os.path.basename(file)):
                    files_by_parser = []
                    if parser in tasks:
                        files_by_parser = tasks[parser]
                    else:
                        tasks[parser] = files_by_parser
                    files_by_parser.append(file)
        print_tasks(tasks)
        with ThreadPoolExecutor(max_workers=len(self.parsers)) as executor:
            futures = []
            for key in tasks:
                parser = key
                files = tasks[key]
                futures.append(executor.submit(worker, parser, files, db_fast_logger))
            for future in as_completed(futures):
                result = future.result()
                print(result)
        db_fast_logger.consolidate_database()
        db = Database(dbname=os.path.join(self.output_dir, "main.db"))
        db.create_extra_tables()
        db.create_views()
        db.create_derived_tables()
