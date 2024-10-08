from mswinif.parsers.winevtx.GenericEvtxParser import GenericEvtxParser
from mswinif.utils import parsed_date


class RDPCoreTS(GenericEvtxParser):
    def __init__(self):
        super().__init__(name="windows_received_tcp_udp_connections")

    def can_handle(self, filename):
        if filename.endswith('.evtx'):
            if "rdpcorets" in filename.strip().lower():
                return True
        return False

    def process(self, filepath):
        collectd_records = []
        for node, err in self.xml_records(filepath):
            if err is not None:
                continue
            sys = self.get_child(node, "System")
            event_time_utc = parsed_date(self.get_child(sys, "TimeCreated").get("SystemTime"))
            event_id = int(self.get_child(sys, "EventID").text)
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            execution = self.get_child(sys, "Execution")
            process_id = execution.get("ProcessID")
            thread_id = execution.get("ThreadID")
            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                for data_item in event_data.getchildren():
                    data_name = data_item.get("Name")
                    data_dict[data_name] = data_item.text
            event_summary = {}
            event_summary[98] = "Successful connection"
            event_summary[131] = "Connection accpeted"
            if 98 == event_id or 131 == event_id:
                insert_dict = {}
                insert_dict["event_id"] = event_id
                insert_dict["event_summary"] = event_summary[event_id]
                insert_dict["event_time_utc"] = event_time_utc
                insert_dict["event_record_no"] = event_record_no
                insert_dict["computer"] = computer
                insert_dict["process_id"] = process_id
                insert_dict["thread_id"] = thread_id
                insert_dict["conn_type"] = data_dict.get("ConnType", "")
                insert_dict["client_ip"] = data_dict.get("ClientIP", "")
                collectd_records.append(insert_dict)
        return collectd_records