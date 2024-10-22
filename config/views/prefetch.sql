create view vw_prefetch_timeline as
select executable_name, executed_at
from prefetch_events
group by 1,2
order by 2 asc;