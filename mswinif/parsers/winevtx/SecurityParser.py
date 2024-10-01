import re
from lxml import etree
from mswinif.parsers.winevtx.GenericEvtxParser import GenericEvtxParser
from mswinif.utils import parsed_date, read_json_file_to_dict

ntstatus_by_code = read_json_file_to_dict(".\\config\\NTSTATUS_by_code.json")
ntstatus_by_hex = read_json_file_to_dict(".\\config\\NTSTATUS_by_hex.json")


def to_lxml(record_xml):
    return etree.fromstring('<?xml version="1.0" encoding="utf-8" standalone="yes" ?>%s' % record_xml)


def remove_non_numeric(s):
    return ''.join([char for char in s if char.isdigit()])


def parse_nt_status(value):
    if value.upper() in ntstatus_by_code:
        return ntstatus_by_code[value.upper()]["description"]
    if value.upper() in ntstatus_by_hex:
        return ntstatus_by_hex[value.upper()]["description"]
    return "undefined"


def parse_yes_no(value):
    elevated_token_map = {
        '%%1843': 'Yes',
        '%%1842': 'No'
    }
    if value in elevated_token_map:
        return elevated_token_map[value]
    if value.strip() in elevated_token_map:
        return elevated_token_map[value]
    return "undefined"


def parse_logon_process_name(value):
    elevated_token_map = {
        'advapi': 'Advanced API - commonly seen in service-related logons',
        'user32': 'User interface dll - commonly graphical interface',
        'ntlmssp': 'NTLM logon - kerberos',
        'winlogon': 'Interactive logon',
        'seclogon': 'RunAs feature',
        'msauth1.0': 'MS auth package - microsoft services',
        'schannel': 'Secure channel'
    }
    if value.lower().strip() in elevated_token_map:
        return elevated_token_map[value.lower().strip()]
    return "undefined"


def parse_authentication_package_name(value):
    elevated_token_map = {
        'kerberos': 'An authentication protocol that uses tickets ',
        'ntlm': 'Older authentication protocol that uses a challenge-response mechanism',
        'msv1_0': 'supports NTLMv1, NTLMv2, and LM (Lan Manager) protocols',
        'wdigest': 'Challenge-response mechanism used in earlier versions of Windows',
        'schannel': 'Secure Channel authentication package used for SSL/TLS',
        'dpa': 'Distributed Password Authentication package for older distributed systems',
        'tsssp': 'The Terminal Services Single Sign-On Provider for remote desktop',
        'negotiate': 'selects the best available protocol (Kerberos or NTLM)'
    }
    if value.lower().strip() in elevated_token_map:
        return elevated_token_map[value.lower().strip()]
    return "undefined"


def impersonation_level(value):
    elevated_token_map = {
        '%%1830': 'Anonymous - cannot impersonate the client',
        '%%1831': 'Identification - Can only obtain information about the client',
        '%%1832': 'Impersonation - Can act as the client',
        '%%1833': 'Delegation - remote impersonation',
    }
    if value in elevated_token_map:
        return elevated_token_map[value]
    if value.strip() in elevated_token_map:
        return elevated_token_map[value]
    return "undefined"


def parse_privilege_list(values):
    privilege_map = {
        "SeTcbPrivilege": "Act as part of the operating system",
        "SeBackupPrivilege": "Back up files and directories",
        "SeCreateTokenPrivilege": "Create a token object",
        "SeDebugPrivilege": "Debug programs",
        "SeEnableDelegationPrivilege": "Enable computer and user accounts to be trusted for delegation",
        "SeAuditPrivilege": "Generate security audits",
        "SeImpersonatePrivilege": "Impersonate a client after authentication",
        "SeLoadDriverPrivilege": "Load and unload device drivers",
        "SeSecurityPrivilege": "Manage auditing and security log",
        "SeSystemEnvironmentPrivilege": "Modify firmware environment values",
        "SeAssignPrimaryTokenPrivilege": "Replace a process-level token",
        "SeRestorePrivilege": "Restore files and directories",
        "SeTakeOwnershipPrivilege": "Take ownership of files or other objects",
    }
    values = re.sub(r'\s+', ' ', values)
    words = re.split(r'[ ,]', values)
    translated_privs = [privilege_map[word] if word in privilege_map else f"unknown: {word}" for word in words]
    return " ".join(translated_privs)


def parse_target_user_name(value: str):
    if value.lower().startswith("dwm"):
        return "Desktop Window Manager"
    if value.lower().startswith("umfd"):
        return "User Mode Font Drive"
    return value

def parse_logon_type(value):
    logon_type_map = {
        "0": "System",
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive",
        "11": "CachedInteractive",
        "12": "CachedRemoteInteractive",
        "13": "CachedUnlock"
    }

    try:
        if str(value) in logon_type_map:
            return logon_type_map[str(value)]
        if remove_non_numeric(value) in logon_type_map:
            return logon_type_map[remove_non_numeric(value)]
        if str(int(value)) in logon_type_map:
            return logon_type_map[str(int(value))]
        if str(int(value, 16)) in logon_type_map:
            return logon_type_map[str(int(value, 16))]
    except Exception:
        return "decoding error"
    return "undefined"


def parse_logon_status(value: str):
    status_map = {
        "0XC000005E": "There are currently no logon servers available to service the logon request",
        "0xC0000064": "User logon with misspelled or bad user account",
        "0xC000006A": "User logon with misspelled or bad password for critical accounts or service accounts",
        "0XC000006D": "This is either due to a bad username or authentication information for critical accounts or service accounts",
        "0xC000006F": "User logon outside authorized hours",
        "0xC0000070": "User logon from unauthorized workstation",
        "0xC0000072": "User logon to account disabled by administrator",
        "0XC000015B": "The user has not been granted the requested logon type (aka logon right) at this machine",
        "0XC0000192": "An attempt was made to logon, but the Netlogon service was not started",
        "0xC0000193": "User logon with expired account",
        "0XC0000413": "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine",
    }
    return status_map[value.upper()] if value.upper() in status_map else "undefined"


def generic_flags_checker(hex_string, bit_dict):
    num = int(hex_string, 16)
    set_bits = []
    for bit_position, meaning in bit_dict.items():
        if num & (1 << bit_position):
            set_bits.append(meaning)
    return set_bits

ticket_options_bitmap = {
    0: "Reserved",
    1: "Forwardable",
    2: "Forwarded",
    3: "Proxiable",
    4: "Proxy",
    5: "Allow-postdate",
    6: "Postdated",
    7: "Invalid",
    8: "Renewable",
    9: "Initial",
    10: "Pre-authent",
    11: "Opt-hardware-auth",
    12: "Transited-policy-checked",
    13: "Ok-as-delegate",
    14: "Request-anonymous",
    15: "Name-canonicalize",
    16: "Unused",
    17: "Unused",
    18: "Unused",
    19: "Unused",
    20: "Unused",
    21: "Unused",
    22: "Unused",
    23: "Unused",
    24: "Unused",
    25: "Unused",
    26: "Disable-transited-check",
    27: "Renewable-ok",
    28: "Enc-tkt-in-skey",
    29: "Unused",
    30: "Renew",
    31: "Validate",
}


def ticket_options_parser(value):
    return generic_flags_checker(value, ticket_options_bitmap)


def get_relations():
    return {
        "TargetLogonId": ["TargetLinkedLogonId", "TargetLogonId", "LogonId"]
    }


class SecurityParser(GenericEvtxParser):
    def __init__(self):
        super().__init__(name="windows_logon")
        regular_events = ["4624", "4672", "4647", "4648", "4625", "4634"]
        active_directory_events = ["4768", "4769", "4776"]
        self.accepted_events = regular_events + active_directory_events
        self.event_map = {
            # Logon ID: relates to 4672(S): Special privileges assigned to new logon
            # Linked Logon ID: Logon ID
            # Logon GUID: relates to 4769 kerberos ticket
            "4624": {
                "name": "An account was successfully logged on",
                "desc": "logon session is created (on destination machine)",

            },
            "4672": {
                "name": "Special PRIVILEGES assigned to new logon - Every SYSTEM logon triggers this event",
                "desc": "Sensitive privileges are assigned to the new logon session",
            },
            "4647": {
                "name": "User initiated logoff - initiated using logoff function",
                "desc": "4647 is more typical for Interactive and RemoteInteractive",
            },
            "4634": {
                "name": "An account was logged off - session no longer exists",
                "desc": "4647 is more typical for Interactive and RemoteInteractive logon types when user was logged off using standard methods. You will typically see both 4647 and 4634 events when logoff procedure was initiated by user.",
            },
            "4648": {
                "name": "A logon was attempted using explicit credentials (Routine Event)",
                "desc": "Occurs in batch-type or with RUNAS. It is a routine event, which periodically occurs. May be initiated from network.",
            },
            "4625": {
                "name": "An account failed to log on",
                "desc": "",
            },
            "4768": {
                "name": "A Kerberos authentication ticket (TGT) was requested",
                "desc": "",
            },
            "4769": {
                "name": "A Kerberos service ticket was requested",
                "desc": "",
            }
        }

        for key in self.event_map:
            self.event_map[key]["logontype"] = parse_logon_type
            self.event_map[key]["elevatedtoken"] = parse_yes_no
            self.event_map[key]["privilegelist"] = parse_privilege_list
            self.event_map[key]["status"] = parse_nt_status
            self.event_map[key]["substatus"] = parse_nt_status
            self.event_map[key]["ticketoptions"] = ticket_options_parser
            self.event_map[key]["authenticationpackagename"] = parse_authentication_package_name
            self.event_map[key]["logonprocessname"] = parse_logon_process_name
            self.event_map[key]["targetusername"] = parse_target_user_name
            self.event_map[key]["virtualaccount"] = parse_yes_no

    def can_handle(self, filename):
        if filename.endswith('.evtx' or filename.endswith('.MTA')):
            if "security" in filename.strip().lower():
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
            execution = self.get_child(sys, "Execution")
            process_id = execution.get("ProcessID")
            thread_id = execution.get("ThreadID")
            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                for data_item in event_data.getchildren():
                    data_name = data_item.get("Name")
                    if data_name.lower() in event_dict:
                        data_dict[f"{data_name}_desc"] = event_dict[data_name.lower()](data_item.text)
                    data_dict[data_name] = data_item.text.strip() if data_item.text is not None else ""
            data_dict["event_id"] = event_id
            data_dict["event_summary"] = event_dict["name"]
            data_dict["event_time_utc"] = event_time_utc
            data_dict["event_record_no"] = event_record_no
            data_dict["computer"] = computer
            data_dict["process_id"] = process_id
            data_dict["thread_id"] = thread_id
            # data_dict["source_xml"] = etree.tostring(node)
            collected_records.append(data_dict)
        return collected_records
