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


create view vw_threats_windows_defender as
select substr(event_time_utc, 0,17) as dt_event, event_data_16 as severity_id, event_data_17, event_data_18, event_data_19, event_data_15, count(*) from windows_defender
where event_data_14='Threat Name'
group by 1,2,3,4,5,6
order by 1 desc;


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
	origin_name
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