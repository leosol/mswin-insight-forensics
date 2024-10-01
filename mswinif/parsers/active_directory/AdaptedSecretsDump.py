import os
import re
from mswinif.parsers.GenericParser import GenericParser
from mswinif.csv_logger.CSVLogger import CSVLogger
from mswinif.common.SecretsDumpTool import SecretsDumpTool
from mswinif import fs_utils

POSSIBLE_SYSTEM_HIVE_NAMES = ["system", "system.hive", "system-hive", "system.bin", "system.reg", "system.raw" ]
# regex = r"^([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$"

def extract_record_from_line(line):
    fields = line.split(':')
    if len(fields) == 7:
        identity = fields[0]
        identity_id = fields[1]
        lm_hash = fields[2]
        nt_hash = fields[3]
        raw_data = line
        index = identity.find('\\')
        if index != -1:
            domain = identity[:index]
        else:
            domain = None
        return{
            "domain": domain,
            "identity": identity,
            "identity_id": identity_id,
            "lm_hash": lm_hash,
            "nt_hash": nt_hash,
            "raw_data": raw_data
        }
    return None

class AdaptedSecretsDump(GenericParser):

    def __init__(self):
        super().__init__(name="secretsdump")
        self.system_hive_pointer = None

    def can_handle(self, file):
        file_name = fs_utils.get_file_without_parent(file).strip().lower()
        if file_name in POSSIBLE_SYSTEM_HIVE_NAMES:
            self.system_hive_pointer = file
        if "ntds.dit.edb" in file.strip().lower():
            return True
        return False

    def process(self, file):
        if self.system_hive_pointer is None:
            print(f"System hive not found. Use one of the names {POSSIBLE_SYSTEM_HIVE_NAMES} and place it in the input dir")
            return
        secrets_dump_result = SecretsDumpTool(tools_dir=self.tools_dir, ntdis_db=file,system_hive=self.system_hive_pointer).execute()
        collected_records = []
        if secrets_dump_result["success"]:
            lines = secrets_dump_result["cmd_stdout"].splitlines()
            for line in lines:
                record = extract_record_from_line(line)
                if record is not None:
                    collected_records.append(record)
        return collected_records

def main():
    print(extract_record_from_line("gdfnet.df\$8J0200-O9L74U1HBIS8:66152:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"))
    print(extract_record_from_line("SAUDE-DC-102$:1104:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"))


if __name__ == "__main__":
    main()