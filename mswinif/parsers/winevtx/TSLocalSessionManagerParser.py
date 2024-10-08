from mswinif.parsers.winevtx.GenericEvtxParser import GenericEvtxParser
from mswinif.utils import parsed_date


class TSLocalSessionManagerParser(GenericEvtxParser):
    def __init__(self):
        super().__init__(name="received_rdp_logon_logoff_and_gui_info")

    def can_handle(self, filename):
        if filename.endswith('.evtx'):
            if "TerminalServices" in filename and "LocalSessionManager" in filename:
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
            if not (21 == event_id or 22 == event_id or 25 == event_id or 40 == event_id or 23 == event_id):
                continue
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            provider = self.get_child(sys, "Provider").get("Name")
            level = self.get_child(sys, "Level").text
            channel = self.get_child(sys, "Channel").text
            security_user_id = self.get_child(sys, "Security").get("UserID")
            data_dict = {}
            event_data = self.get_child(node, "EventData")
            if event_data is not None:
                pos = 0
                for data_item in event_data.getchildren():
                    data_dict["event_data_"+str(pos)] = data_item.text
                    pos = pos+1
            usr_data = self.get_child(node, "UserData")
            usr_data_dict = {}
            if usr_data is not None:
                usr_data_evt_xml = self.get_child2(usr_data, "EventXML")
                usr_data_evt_xml_user = self.get_child2(usr_data_evt_xml, "User")
                usr_data_evt_xml_session_id = self.get_child2(usr_data_evt_xml, "SessionID")
                usr_data_evt_xml_address = self.get_child2(usr_data_evt_xml, "Address")
                usr_data_evt_xml_session = self.get_child2(usr_data_evt_xml, "Session")
                usr_data_evt_xml_reason = self.get_child2(usr_data_evt_xml, "Reason")
                if usr_data_evt_xml is not None:
                    if usr_data_evt_xml_user is not None:
                        usr_data_dict["param1_user"] = usr_data_evt_xml_user.text
                    if usr_data_evt_xml_session_id is not None:
                        usr_data_dict["param2_session_id"] = usr_data_evt_xml_session_id.text
                    if usr_data_evt_xml_address is not None:
                        usr_data_dict["param3_address"] = usr_data_evt_xml_address.text
                    if usr_data_evt_xml_session is not None:
                        usr_data_dict["param4_session"] = usr_data_evt_xml_session.text
                    if usr_data_evt_xml_reason is not None:
                        usr_data_dict["param5_reason"] = usr_data_evt_xml_reason.text
                        if usr_data_evt_xml_reason.text is not None:
                            reason_id = usr_data_evt_xml_reason.text.strip()
                            if "0" == reason_id:
                                usr_data_dict["param5_reason_str"] = "No additional information available for the disconnection"
                            if "2" == reason_id:
                                usr_data_dict["param5_reason_str"] = "An administrative tool was used to disconnect the session"
                            if "5" == reason_id:
                                usr_data_dict["param5_reason_str"] = "User connected to the machine, forcing the disconnection of another"
                            if "11" == reason_id:
                                usr_data_dict["param5_reason_str"] = "User closing the RDP window or an administrative tool being used from the same session"
                            if "12" == reason_id:
                                usr_data_dict["param5_reason_str"] = "Disconnection was initiated by the user logging off his session"
            execution = self.get_child(sys, "Execution")
            process_id = execution.get("ProcessID")
            thread_id = execution.get("ThreadID")
            event_summary = {}
            event_summary[21] = "RDP and session ID"
            event_summary[22] = "Shell started for RDP (probably GUI interface)"
            event_summary[25] = "RDP is reconnecting to a session ID"
            event_summary[40] = "Session has been disconnected"
            event_summary[23] = "RDP Logoff"
            if 21 == event_id or 22 == event_id or 25 == event_id or 40 == event_id or 23 == event_id:
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
                insert_dict["param1_user"] = usr_data_dict.get("param1_user", "")
                insert_dict["param2_session_id"] = usr_data_dict.get("param2_session_id", "")
                insert_dict["param3_address"] = usr_data_dict.get("param3_address", "")
                insert_dict["param4_session"] = usr_data_dict.get("param4_session", "")
                insert_dict["param5_reason"] = usr_data_dict.get("param5_reason", "")
                insert_dict["param5_reason_str"] = usr_data_dict.get("param5_reason_str", "")
                collected_records.append(insert_dict)
        return collected_records


