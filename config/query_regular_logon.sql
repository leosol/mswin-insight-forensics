--select event_id, LogonType, LogonType_desc, count(*) from windows_logon group by 1,2,3 order by count(*) desc
create view vw_interactive_logons as
select 
	event_id, event_record_no, event_summary, event_time_utc,
	computer, WorkstationName,
	ElevatedToken, ImpersonationLevel, RestrictedAdminMode,
	IpAddress, IpPort,
	TransmittedServices, AuthenticationPackageName, KeyLength, LmPackageName,
	LogonGuid, LogonProcessName, LogonType, LogonType_desc,
	PrivilegeList, PrivilegeList_desc,
	process_id, ProcessId, ProcessName, thread_id,
	Status, Status_desc, SubStatus, SubStatus_desc,	FailureReason,
	SubjectDomainName, SubjectLogonId, SubjectUserName, SubjectUserSid,
	TargetDomainName, TargetInfo, TargetLinkedLogonId, TargetLogonGuid, TargetLogonId, TargetOutboundDomainName, TargetOutboundUserName, TargetServerName, TargetUserName, TargetUserSid,
	VirtualAccount
from windows_logon a
where a.LogonType_desc in ('Interactive', 'Unlock')
order by event_time_utc desc;



