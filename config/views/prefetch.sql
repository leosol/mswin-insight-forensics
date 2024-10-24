create view vw_prefetch_timeline as
select executable_name, executed_at, executed_at_local_tz
from prefetch_events
group by 1,2,3
order by 2 asc;