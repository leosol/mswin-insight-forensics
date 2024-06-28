from mswinif.csv_logger.CSVLogger import CSVLogger
from mswinif.csv_logger.CSVToSQLite import CSVToSQLite


class SQLiteDBFastLogger:
    def __init__(self, basedir):
        self.basedir = basedir
        self.loggers = {}

    def add_logger(self, table_name, column_names):
        self.loggers[table_name] = CSVLogger(basedir=self.basedir, filename=f"{table_name}.csv")
        self.loggers[table_name].open_log(column_names)

    def log_data(self, table_name, row_data):
        self.loggers[table_name].append_log(row_data)

    def consolidate_database(self):
        csv_to_sqlite = CSVToSQLite(dest_dir=self.basedir)
        csv_to_sqlite.import_csv_dir_into_database(self.basedir)

    def close(self):
        for table_name in self.loggers:
            self.loggers[table_name].close_log()

