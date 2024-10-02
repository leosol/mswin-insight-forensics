from mswinif.parsers.winevtx.GenericEvtxParser import GenericEvtxParser
from mswinif.utils import parsed_date


def parse_level(value):
    level_map = {
        "2": "Error",
        "3": "Warning",
        "4": "Information",
    }
    try:
        if str(value) in level_map:
            return level_map[str(value)]
    except Exception:
        return "decoding error"
    return "undefined"

class WindowsDefenderParser(GenericEvtxParser):
    def __init__(self):
        super().__init__(name="windows_defender")
        self.event_map = {
            "1000": {
                "name": "Malware Detection",
                "desc": "Windows Defender has detected malware on the system",
            },
            "1001": {
                "name": "Malware Detection Details",
                "desc": "detailed information about the malware detected"
            },
            "1002": {
                "name": "Scan Started",
                "desc": "start of a malware scan initiated by Windows Defender"
            },
            "1013": {
                "name": "Scan Completed",
                "desc": "a malware scan has completed"
            },
            "1116": {
                "name": "Threat Action Success",
                "desc": "a specified action was successfully taken against a detected threat"
            },
            "1117": {
                "name": "Threat Action Failure",
                "desc": "an attempt to take action against a detected threat failed"
            },
            "1118": {
                "name": "Quarantine Action",
                "desc": "This event logs that a file has been successfully quarantined"
            },
            "1150": {
                "name": "Windows Defender Service Started",
                "desc": "Windows Defender Service Started"
            },
            "1151": {
                "name": "Windows Defender Service Stopped",
                "desc": "Windows Defender service has stopped"
            },
            "2000": {
                "name": "Action Required",
                "desc": "an action is required by the user or administrator to respond to a threat detected by Windows Defender"
            },
            "2001": {
                "name": "User Action Taken",
                "desc": "the user or administrator has taken a specific action in response to a threat"
            },
            "2002": {
                "name": "Action Failed",
                "desc": "an action taken in response to a threat has failed"
            },
            "2010": {
                "name": "Defender Update",
                "desc": "Windows Defender has successfully updated its virus definitions or software"
            },
            "2014": {
                "name": "Defender Update Failure",
                "desc": "an attempt to update Windows Defender failed"
            },
            "5004": {
                "name": "PowerShell Script Execution",
                "desc": "PowerShell script has been executed and logged by Windows Defender"
            },
            "5007": {
                "name": "PowerShell Event Not Checked",
                "desc": "a PowerShell event was not monitored or checked by Windows Defender, suggesting a possible oversight in the security monitoring"
            },
        }
        for key in self.event_map:
            self.event_map[key]["level"] = parse_level

    def can_handle(self, filename):
        if filename.endswith('.evtx'):
            if "Windows Defender" in filename:
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
            if str(event_id) not in self.event_map:
                continue
            else:
                event_dict = self.event_map[str(event_id)]
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            provider = self.get_child(sys, "Provider").get("Name")
            level = self.get_child(sys, "Level").text
            channel = self.get_child(sys, "Channel").text
            security_user_id = self.get_child(sys, "Security").get("UserID")

            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                for data_item in event_data.getchildren():
                    data_name = data_item.get("Name")
                    if data_name is None:
                        continue
                    data_name = data_name.lower().strip()
                    if data_name in event_dict:
                        data_dict[f"{data_name}_desc"] = event_dict[data_name.lower()](data_item.text)
                    data_dict[data_name] = data_item.text.strip() if data_item.text is not None else ""
            data_dict["event_id"] = event_id
            data_dict["event_summary"] = event_dict["name"]
            data_dict["event_desc"] = event_dict["desc"]
            data_dict["event_time_utc"] = event_time_utc
            data_dict["event_record_no"] = event_record_no
            data_dict["computer"] = computer
            data_dict["provider"] = provider
            data_dict["level"] = level
            data_dict["level_desc"] = parse_level(level)
            data_dict["channel"] = channel
            data_dict["security_user_id"] = security_user_id
            collected_records.append(data_dict)
        return collected_records
