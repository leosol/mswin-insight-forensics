from mswinif.parsers.winevtx.GenericEvtxParser import GenericEvtxParser
from mswinif.utils import parsed_date


class PowerShellParser(GenericEvtxParser):
    def __init__(self):
        super().__init__(name="power_shell_script_logging")

    def can_handle(self, filename):
        if filename.endswith('.evtx'):
            if "PowerShell" in filename:
                return True
        return False

    def process(self, filepath):
        collected_records = []
        for node, err in self.xml_records(filepath):
            if err is not None:
                continue
            sys = self.get_child(node, "System")
            event_time_utc = parsed_date(self.get_child(sys, "TimeCreated").get("SystemTime"))
            event_id = int(self.get_child(sys, "EventID").text)
            #if not (4104 == event_id or 4103 == event_id):
            #    continue
            #self.print_node(node)
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            provider = self.get_child(sys, "Provider").get("Name")
            level = self.get_child(sys, "Level").text
            channel = self.get_child(sys, "Channel").text
            security_user_id = self.get_child(sys, "Security").get("UserID")
            script_block_id = ""
            script_block_text = ""
            script_msg_number = ""
            script_msg_total = ""
            script_path = ""
            script_session_id = ""
            possible_command_in_str = ""
            data_dict = {}
            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                pos = 0
                for data_item in event_data.getchildren():
                    data_name = data_item.get("Name")
                    data_text = data_item.text
                    data_dict["event_data_" + str(pos)] = data_name
                    pos = pos + 1
                    data_dict["event_data_" + str(pos)] = data_text
                    pos = pos + 1
                    if data_name == "ScriptBlockId":
                        script_block_id = data_text
                    if data_name == "ScriptBlockText":
                        script_block_text = data_text
                    if data_name == "MessageNumber":
                        script_msg_number = data_text
                    if data_name == "MessageTotal":
                        script_msg_total = data_text
                    if data_name == "Path":
                        script_path = data_text
                    if data_name == "SessionId":
                        script_session_id = data_text
                    else:
                        if data_text is not None:
                            uuid_sample = "0e74241d-2b33-4abb-a22f-aefee936424d"
                            if len(data_text) == len(uuid_sample) and data_text.count("-") == uuid_sample.count("-"):
                                script_session_id = data_text
                    if data_text is not None and "command" in data_text.lower():
                        possible_command_in_str = data_text.replace(' ', '\n')

            execution = self.get_child(sys, "Execution")
            try:
                process_id = execution.get("ProcessID")
                thread_id = execution.get("ThreadID")
            except Exception as e:
                process_id = ""
                thread_id = ""
            event_summary = {}
            event_summary[1026] = "PowerShellWebAccess - 1026 (keep alive?)"
            event_summary[1025] = "PowerShellWebAccess - 1025 (script error?)"
            event_summary[784] = "PowerShellWebAccess - 784 (new session?)"
            event_summary[776] = "PowerShellWebAccess - 776 (disconnect)"
            event_summary[769] = "PowerShellWebAccess - 769 (WSMAN - Windows Remote Management)"
            event_summary[514] = "PowerShellWebAccess - 514 Connecting to remote server failed"
            event_summary[261] = "PowerShellWebAccess - 261 An error occurred during the sign-in process"
            event_summary[259] = "PowerShellWebAccess - 259 An authorization failure occurred"
            event_summary[260] = "PowerShellWebAccess - 260 (keep alive/success login?)"
            event_summary[257] = "PowerShellWebAccess - 257 Wrong Credentials"

            event_summary[600] = "PowerShell LifeCycle - 600 Alias, Registry, Env, FS, Function, etc"
            event_summary[403] = "PowerShell LifeCycle - 403 Stopped"
            event_summary[300] = "PowerShell LifeCycle - 300 Integrity"

            event_summary[53504] = "PowerShell 53504 - EmptyLog?"
            event_summary[40961] = "PowerShell 40961 - EmptyLog?"
            event_summary[40962] = "PowerShell 40962 - EmptyLog?"
            event_summary[12039] = "PowerShell 12039 - EmptyLog?"
            event_summary[8196] = "PowerShell 8196 - EmptyLog?"
            event_summary[8195] = "PowerShell 8195 - EmptyLog?"

            event_summary[32784] = "PowerShell Client to Remote 32784 - Failed to connect"
            event_summary[8198] = "PowerShell Client to Remote? 8198 - keep alive?"
            event_summary[8197] = "PowerShell Client to Remote? 8197 - Broken or Opening?"
            event_summary[8194] = "PowerShell Client to Remote? 8197 - InstanceId? RunSpace?"
            event_summary[8193] = "PowerShell Client to Remote? 8193 - InstanceId? RunSpace?"

            event_summary[4104] = "PowerShell 4104 - Execute Command"
            event_summary[32784] = "PowerShell 32784 - Failed to Connect"

            if event_id not in event_summary:
                event_summary[event_id] = "PowerShell event not checked "+str(event_id)

            if True:
                insert_dict = {}
                insert_dict["event_id"] = event_id
                insert_dict["event_summary"] = event_summary[event_id]
                insert_dict["event_time_utc"] = event_time_utc
                insert_dict["event_record_no"] = event_record_no
                insert_dict["computer"] = computer
                insert_dict["process_id"] = process_id
                insert_dict["thread_id"] = thread_id
                insert_dict["provider"] = provider
                insert_dict["level"] = level
                insert_dict["channel"] = channel
                insert_dict["security_user_id"] = security_user_id
                insert_dict["event_data_0"] = data_dict.get("event_data_0", "")
                insert_dict["event_data_1"] = data_dict.get("event_data_1", "")
                insert_dict["event_data_2"] = data_dict.get("event_data_2", "")
                insert_dict["event_data_3"] = data_dict.get("event_data_3", "")
                insert_dict["event_data_4"] = data_dict.get("event_data_4", "")
                insert_dict["event_data_5"] = data_dict.get("event_data_5", "")
                insert_dict["event_data_6"] = data_dict.get("event_data_6", "")
                insert_dict["event_data_7"] = data_dict.get("event_data_7", "")
                insert_dict["event_data_8"] = data_dict.get("event_data_8", "")
                insert_dict["event_data_9"] = data_dict.get("event_data_9", "")
                insert_dict["event_data_10"] = data_dict.get("event_data_10", "")
                insert_dict["event_data_11"] = data_dict.get("event_data_11", "")
                insert_dict["event_data_12"] = data_dict.get("event_data_12", "")
                insert_dict["event_data_13"] = data_dict.get("event_data_13", "")
                insert_dict["event_data_14"] = data_dict.get("event_data_14", "")
                insert_dict["event_data_15"] = data_dict.get("event_data_15", "")
                insert_dict["event_data_16"] = data_dict.get("event_data_16", "")
                insert_dict["event_data_17"] = data_dict.get("event_data_17", "")
                insert_dict["event_data_18"] = data_dict.get("event_data_18", "")
                insert_dict["event_data_19"] = data_dict.get("event_data_19", "")
                insert_dict["script_block_id"] = script_block_id
                insert_dict["script_block_text"] = script_block_text
                insert_dict["script_msg_number"] = script_msg_number
                insert_dict["script_msg_total"] = script_msg_total
                insert_dict["script_path"] = script_path
                insert_dict["script_session_id"] = script_session_id
                insert_dict["possible_command_in_str"] = possible_command_in_str
                collected_records.append(insert_dict)
        return collected_records


