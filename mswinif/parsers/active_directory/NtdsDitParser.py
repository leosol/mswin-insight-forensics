import os
from dissect.esedb import EseDB
from mswinif.parsers.GenericParser import GenericParser
from mswinif.csv_logger.CSVLogger import CSVLogger


class NtdsDitParser(GenericParser):
    def __init__(self):
        super().__init__(name="ntds_dit")
        self.qtd_ntds_dit = 0

    def can_handle(self, file):
        if "ntds.dit.edb" in file.strip().lower():
            return True
        return False

    def process(self, file):
        collected_data = []
        parser_output_dir = os.path.join(self.output_dir, f"ntds_dit_edb_{self.qtd_ntds_dit}")
        if not os.path.exists(parser_output_dir):
            os.makedirs(parser_output_dir)
        with open(file, "rb") as fh:
            db = EseDB(fh)
            for table in db.tables():
                table_name = table.name
                column_names = table.column_names
                csv_logger = CSVLogger(basedir=parser_output_dir, filename=f"{table_name}.csv", remove_existing=True)
                csv_logger.open_log(column_names)
                err_count = 0
                success_count = 0
                for record in table.records():
                    try:
                        item = record.as_dict()
                        data = [item[key] for key in item]
                        csv_logger.append_log(data)
                        success_count = success_count + 1
                    except:
                        err_count = err_count + 1
                csv_logger.close_log()
                self.pending_files.append_pending_file(file_path=csv_logger.file_path)
                collected_data.append({
                    "file_name": file,
                    "table_name": table_name,
                    "imported_rows": success_count,
                    "failed_rows": err_count,
                })
        self.qtd_ntds_dit = self.qtd_ntds_dit + 1
        return collected_data

