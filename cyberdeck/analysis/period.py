from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime


def publication_date(event):
    if isinstance(event, dict):
        value = event.get("published_at") or (event.get("technical_validation") or {}).get("published_at")
    else:
        value = event.published_at or (event.technical_validation or {}).get("published_at")
    if not value:
        return None
    value = str(value).strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError):
            try:
                parsed = datetime.strptime(value, "%Y%m%dT%H%M%SZ")
            except ValueError:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date()


def select_period_events(context, events):
    """Include undated evidence explicitly, but exclude dated outside-period records."""
    start = date.fromisoformat(context.organization.analysis_start_date)
    end = date.fromisoformat(context.organization.analysis_end_date)
    selected = []
    excluded = {event.id: event for event in context.excluded_period_events}
    for event in events:
        published = publication_date(event)
        if published is None:
            selected.append(event.model_copy(update={
                "tags": list(dict.fromkeys([*event.tags, "date_unavailable", "period_membership_unverified"])),
                "technical_validation": {**(event.technical_validation or {}), "period_membership": "unverified", "publication_date_status": "unavailable"},
            }))
        elif not start <= published <= end:
            excluded[event.id] = event
        else:
            selected.append(event.model_copy(update={"age_days": (end - published).days}))
    context.excluded_period_events = list(excluded.values())
    context.metrics["analysis_period"] = {
        "start_date": start.isoformat(), "end_date": end.isoformat(),
        "timezone": "UTC", "inclusive": True, "date_basis": "publication_date",
        "included_records": len(selected),
        "undated_records": sum(publication_date(item) is None for item in selected),
        "dated_in_period_records": sum(publication_date(item) is not None for item in selected),
        "out_of_period_records": len(excluded),
        "limitation": "Undated records are included in the analysis; their membership in the selected period is unverified. Current observations do not establish historical conditions.",
    }
    return selected
