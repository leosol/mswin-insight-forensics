create table if not exists derived_powershell_script_blocks (id INTEGER PRIMARY KEY,
 event_id TEXT,
 script_start TEXT,
 event_summary TEXT,
 computer TEXT,
 script_block_id TEXT,
 script_hash TEXT,
 script_msg_total TEXT,
 script_block_assembled TEXT );

create view vw_interactive_logons as
select
event_record_no,
event_time_utc,
event_id,
event_summary,
computer,
WorkstationName,
LogonType,
LogonType_desc,
SubjectDomainName,
SubjectUserName,
TargetLogonId,
TargetDomainName,
LogonProcessName,
LogonProcessName_desc,
ProcessName,
IpAddress,
IpPort,
TargetUserName,
TargetUserName_desc,
TargetUserSid
from windows_logon
where LogonType_desc in ('Interactive');


create view vw_windows_defender_scans as
select
	event_time_utc,
	event_id,
	event_summary,
	event_desc
	event_record_no,
	domain,
	computer,
	level,
	product_name,
	product_version,
	scan_id,
	scan_parameters,
	scan_type,
	user
from windows_defender
where event_id in ('1013', '1002')
order by event_time_utc desc;

create view vw_windows_defender_service as
select
	event_time_utc,
	event_id,
	event_summary,
	event_desc
	event_record_no,
	domain,
	computer,
	level,
	product_name,
	as_security_intelligence_creation_time,
	as_security_intelligence_version,
	av_security_intelligence_creation_time,
	av_security_intelligence_version,
	platform_up_to_date,
	platform_version,
	product_status,
	bm_state,
	oa_state,
	rtp_state,
	ioav_state,
	last_as_security_intelligence_age,
	last_av_security_intelligence_age,
	last_full_scan_age
from windows_defender
where event_id in ('1150', '1151')
order by event_time_utc desc;


create view vw_windows_defender_threat_actions as
select
	event_time_utc,
	event_id,
	event_summary,
	event_desc
	event_record_no,
	domain,
	computer,
	level,
	product_name,
	action_id,
	action_name,
	additional_actions_id,
	additional_actions_string,
	category_id,
	category_name,
	detection_id,
	detection_time,
	detection_user,
	engine_version,
	error_code,
	error_description,
	fwlink,
	origin_id,
	origin_name,
	path,
	process_name,
	severity_id,
	severity_name,
	source_id,
	source_name,
	source_path,
	threat_id,
	threat_name,
	type_id,
	type_name
from windows_defender
where event_id in ('1116', '1117', '1118','2001', '2000','2002')
order by event_time_utc desc;

create view vw_windows_defender_powershell_events as
select
	event_time_utc,
	event_id,
	event_summary,
	event_desc
	event_record_no,
	domain,
	computer,
	level,
	product_name,
	level,
	level_desc,
	old_value,
	new_value
from windows_defender
where event_id in ('5004', '5007')
order by event_time_utc desc;


create view vw_logons_elevated_tokens_analytic as
select event_time_utc, event_id, event_summary, LogonType_desc, IpAddress, WorkstationName, LogonProcessName, ElevatedToken_desc,
VirtualAccount_desc, PrivilegeList, PrivilegeList_desc, TargetDomainName, TargetLinkedLogonId,
TargetLogonId, TargetUserName, TargetUserName_desc, AuthenticationPackageName, AuthenticationPackageName_desc, ImpersonationLevel
from windows_logon
where ElevatedToken_desc='Yes';

create view vw_logons_elevated_tokens_quantitative as
select substr(event_time_utc, 0, 12) as dt_event, event_id, event_summary, LogonType_desc as LogonType, IpAddress, WorkstationName, TargetUserName, count(*) from vw_logons_elevated_tokens
where TargetUserName not in ('DWM-1', 'UMFD-0', 'UMFD-1')
group by 1, 2, 3, 4, 5, 6,7
order by 1 desc;


create view if not exists vw_summary_received_tcp_udp_connections
                as
                select
                    substr(event_time_utc, 0, 11) as dt_event,
                    event_summary,
                    computer,
                    conn_type,
                    client_ip,
                    count(*) as qtd
                from windows_received_tcp_udp_connections
                group by 1,2,3,4,5
                order by dt_event desc;

create view if not exists vw_summary_received_rdp_logon_logoff_and_gui_info as
            select
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary,
                computer,
                provider,
                param1_user,
                param3_address,
                count(*) as qtd
            from received_rdp_logon_logoff_and_gui_info
            group by 1,2,3,4,5,6
            order by dt_event desc;


create view if not exists vw_summary_made_rdp_outgoing as
            select
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary,
                computer,
                provider,
                event_data_0,
                event_data_1,
                event_data_2,
                count(*) as qtd
            from made_rdp_outgoing
            group by 1,2,3,4,5,6,7
            order by dt_event desc;

create view if not exists vw_summary_windows_received_rdp_logon as
            select
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary,
                computer,
                param1_user,
                param2_domain,
                param3_IP_addr,
                count(*) as qtd
            from windows_received_rdp_logon
            group by 1,2,3,4,5,6
            order by dt_event desc;


create view if not exists vw_summary_kaspersky_endpoint_events as
            select
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary,
                computer,
                count(*) as qtd
            from kaspersky_endpoint_events
            group by 1,2,3
            order by dt_event desc;


create view if not exists vw_summary_symantec_endpoint_events as
                    select
                        substr(event_time_utc, 0, 11) as dt_event,
                        event_summary,
                        computer,
                        count(*) as qtd
                    from symantec_endpoint_events
                    group by 1,2,3
                    order by dt_event desc;


create view if not exists vw_summary_powershell_web_access
                as
                select
                    substr(event_time_utc, 0, 11) as dt_event,
                    event_id,
                    event_summary,
                    computer,
                    count(*) as qtd
                from power_shell_script_logging
                where channel = 'Microsoft-Windows-PowerShellWebAccess/Operational'
                group by 1,2,3
                    order by dt_event desc;


create view if not exists vw_powershell_web_access_user_target_node
                as
                select * from power_shell_script_logging
                where channel = 'Microsoft-Windows-PowerShellWebAccess/Operational'
                    and event_data_0 = 'UserName'
                    and event_data_2 = 'TargetNode'
                order by
                    event_time_utc desc;


create view if not exists vw_powershell_script_blocks
                as
                select
                    event_id,
                    event_summary,
                    computer,
                    script_block_id,
                    script_msg_total,
                    count(distinct(script_msg_number)) as qtd_items,
                    min(event_time_utc) script_start,
                    max(event_time_utc) script_end
                from power_shell_script_logging
                where
                    length(script_block_id) > 10
                group by 1,2,3,4,5
                order by 7 desc;


create view if not exists vw_powershell_script_paths
                as
                select * from power_shell_script_logging
                where length(script_path) > 10
                order by
                    event_time_utc desc;

create view if not exists vw_summary_powershell_script_blocks
                as
                select
                    substr(script_start, 0, 11) as script_start,
                    computer,
                    event_id,
                    event_summary,
                    count(*)
                from vw_powershell_script_blocks
                group by 1,2,3,4
                order by 1 desc;