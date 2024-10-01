from mswinif.common.tool import BaseTool
from mswinif.common.command import Command
from mswinif import fs_utils, utils
import sys
import os
from os.path import expanduser


class SecretsDumpTool(BaseTool):
    def __init__(self, tools_dir=None, ntdis_db=None, system_hive=None):
        python_executable = sys.executable
        tool_entry = os.path.join(tools_dir, "secretsdump.py")
        # -ntds .\input\ntds.dit.edb -system .\input\SYSTEM-hive LOCAL
        command_cmd = [python_executable, tool_entry, "-ntds", ntdis_db, "-system",
                       system_hive, "LOCAL"]
        cmd = Command(cmd=command_cmd)
        super().__init__(name=self.__class__.__name__,
                         description="SecretsDumpTool",
                         cmd=cmd, options={
            })

        self.ntdis_db = ntdis_db
        self.system_hive = system_hive


    def before_exec(self):
        if not os.path.exists(self.ntdis_db):
            raise RuntimeError(f"File does not exist {self.ntdis_db}")
        if not os.path.exists(self.system_hive):
            raise RuntimeError(f"File does not exist {self.system_hive}")

    def after_exec(self):
        pass
