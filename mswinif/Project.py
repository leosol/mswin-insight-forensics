import os
from mswinif.utils import list_files
from mswinif.parsers.winevtx import *
from mswinif.parsers.active_directory.NtdsDitParser import NtdsDitParser
from mswinif.parsers.active_directory.AdaptedSecretsDump import AdaptedSecretsDump
from mswinif.csv_logger.SQLiteDBFastLogger import SQLiteDBFastLogger
from mswinif.csv_logger.Database import Database
from mswinif.PendingFiles import PendingFiles
from mswinif.parsers.windowspf.WindowsPrefetchParser import WindowsPrefetchParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import pytz

def print_tasks(tasks: dict):
    for key in tasks:
        cls_name = key.__class__.__name__
        task_name = key.name
        qtd_files = len(tasks[key])
        print(f"Parser {cls_name} has {qtd_files} to process and will save data to {task_name}")

def worker(parser, files, db_fast_logger: SQLiteDBFastLogger):
    cls_name = parser.__class__.__name__
    tbl_name = parser.name
    qtd_items = 0
    all_collected_items = []
    for file in files:
        collected_items = parser.process(file)
        parser.post_process(collected_items)
        all_collected_items = all_collected_items + collected_items
    if len(all_collected_items) > 0:
        header = set()
        for item in all_collected_items:
            for key in item:
                header.add(key)
        header = sorted(header, key=str.lower)
        db_fast_logger.add_logger(tbl_name, header)
        for item in all_collected_items:
            values = []
            for h in header:
                values.append(item[h] if h in item else "")
            assert len(header) == len(values)
            db_fast_logger.log_data(tbl_name, values)
            qtd_items = qtd_items + 1
        db_fast_logger.flush(tbl_name)

    return f"{cls_name} processed {qtd_items} that were saved to {tbl_name}"


class Project:
    def __init__(self, config_dir, input_dir, output_dir, tools_dir, tmp_dir):
        self.config_dir = config_dir
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.tools_dir = tools_dir
        self.tmp_dir = tmp_dir
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
        #self.parsers.append(NtdsDitParser())
        self.parsers.append(WindowsPrefetchParser())
        self.parsers.append(AdaptedSecretsDump())
        self.pending_files = PendingFiles()
        self._configure_parsers()


    def _configure_parsers(self):
        for parser in self.parsers:
            parser.configure(tmp_dir=self.tmp_dir, output_dir=self.output_dir, input_dir=self.input_dir,
                             tools_dir=self.tools_dir, pending_files=self.pending_files)

    def process(self):
        collected_files = list_files(self.input_dir)
        db_fast_logger = SQLiteDBFastLogger(basedir=self.output_dir)
        tasks = dict()
        for file in collected_files:
            for parser in self.parsers:
                if parser.can_handle(file):
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
        views_sql = list_files(os.path.join(self.config_dir, 'views'))
        for sql_file in views_sql:
            db_fast_logger.exec_post_create(sql_file)
        db = Database(dbname=os.path.join(self.output_dir, "main.db"))
        db.create_extra_tables()
        db.create_derived_tables()
