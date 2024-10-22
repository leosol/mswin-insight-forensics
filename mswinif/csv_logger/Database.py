import sqlite3
import hashlib
import traceback
from sqlite3 import Error

class Database:
    def __init__(self, dbname):
        if dbname is None:
            dbname = 'winevtx.db'
        self.conn = sqlite3.connect(dbname)
        self.c = self.conn.cursor()

    def close(self):
        self.c.close()
        self.conn.close()

    def create_extra_tables(self):
        sql = 'create table if not exists derived_powershell_script_blocks (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' script_start TEXT, ' \
              ' event_summary TEXT, ' \
              ' computer TEXT, ' \
              ' script_block_id TEXT, ' \
              ' script_hash TEXT, ' \
              ' script_msg_total TEXT, ' \
              ' script_block_assembled TEXT )'
        #self.c.execute(sql)
        self.execute_query(sql)

    def create_derived_tables(self):
        print("creating derived tables...")
        sql_find_script_blocks = """select
                                    script_start,
                                    event_id,
                                    event_summary,
                                    computer,
                                    script_block_id,
                                    script_msg_total,
                                    qtd_items
                                from vw_powershell_script_blocks
                                order by script_start desc"""
        sql_find_one = """select
                            script_block_id, 
                            script_msg_number,
                            script_block_text,
                            possible_command_in_str
                        from power_shell_script_logging
                        where script_block_id = ?
                        order by cast(script_msg_number as int) asc"""
        # self.c.execute(sql_find_script_blocks)
        if self.execute_query(sql_find_script_blocks):
            all_items = self.c.fetchall()
            for item in all_items:
                script_start = item[0]
                event_id = item[1]
                event_summary = item[2]
                computer = item[3]
                script_block_id = item[4]
                script_msg_total = item[5]
                self.c.execute(sql_find_one, [script_block_id])
                block_items = self.c.fetchall()
                buffer = ""
                for block_item in block_items:
                    item_script_block_id = block_item[0]
                    item_script_msg_number = block_item[1]
                    item_script_block_text = block_item[2]
                    item_possible_command_in_str = block_item[3]
                    #buffer = buffer + "#Script block "+str(item_script_msg_number)+" of "+str(script_msg_total)+"\r\n"
                    buffer = buffer + item_script_block_text
                buffer_hash = hashlib.md5(buffer.encode('utf-8')).hexdigest()
                insert_dict = {}
                insert_dict["event_id"] = event_id
                insert_dict["event_summary"] = event_summary
                insert_dict["script_start"] = script_start
                insert_dict["computer"] = computer
                insert_dict["script_block_id"] = script_block_id
                insert_dict["script_block_assembled"] = buffer
                insert_dict["script_hash"] = buffer_hash
                insert_dict["script_msg_total"] = script_msg_total
                self.insert_derived_powershell_script_blocks(insert_dict)

    def insert_derived_powershell_script_blocks(self, insert_dict):
        sql = "insert into derived_powershell_script_blocks (" \
              " event_id," \
              " event_summary, " \
              " script_start, " \
              " computer," \
              " script_block_id," \
              " script_block_assembled," \
              " script_hash," \
              " script_msg_total) " \
              "values (?, ?, ?, ?, ?, ?, ?, ?)"
        self.c.execute(sql, list(insert_dict.values()))
        self.conn.commit()

    def execute_query(self, sql: str, data=None):
        try:
            if data is not None:
                self.c.execute(sql, data)
                return True
            else:
                self.c.execute(sql)
                return True
        except Exception:
            tb_exception = traceback.format_exc()
            print(tb_exception)
            return False


