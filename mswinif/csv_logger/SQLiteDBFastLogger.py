from mswinif.csv_logger.CSVLogger import CSVLogger
from mswinif.csv_logger.CSVToSQLite import CSVToSQLite


class SQLiteDBFastLogger:
    def __init__(self, basedir):
        self.basedir = basedir
        self.loggers = {}
        self.csv_to_sqlite = None

    def add_logger(self, table_name, column_names):
        self.loggers[table_name] = CSVLogger(basedir=self.basedir, filename=f"{table_name}.csv")
        self.loggers[table_name].open_log(column_names)

    def log_data(self, table_name, row_data):
        self.loggers[table_name].append_log(row_data)

    def flush(self, table_name):
        self.loggers[table_name].flush()

    def consolidate_database(self):
        self.csv_to_sqlite = CSVToSQLite(dest_dir=self.basedir)
        self.csv_to_sqlite.import_csv_dir_into_database(self.basedir)

    def close(self):
        for table_name in self.loggers:
            self.loggers[table_name].close_log()

    def exec_post_create(self, sql_file):
        if self.csv_to_sqlite:
            self.csv_to_sqlite.execute_sql_file(sql_file)