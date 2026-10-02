from datetime import UTC, datetime

import pytest

from sentinel.agents.enrich import enrichment_query, launch_context
from sentinel.agents.triage import build_user_message
from sentinel.schemas import Alert, Event, ProcessInfo

CMD = "C:\\Windows\\System32\\cmd.exe"


def _event(parent_image, parent_cmd="", image=CMD):
    parent = ProcessInfo(image=parent_image, command_line=parent_cmd) if parent_image else None
    return Event(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        source="windows_sysmon",
        host="host-1",
        process=ProcessInfo(image=image, command_line="cmd /c whoami", parent=parent),
        raw={},
        untrusted_fields=[],
    )


@pytest.mark.parametrize(
    ("parent", "parent_cmd", "expected"),
    [
        ("C:\\Windows\\System32\\services.exe", "", "run as a Windows service"),
        ("c:\\windows\\system32\\inetsrv\\w3wp.exe", '-ap "OWA"', "web server worker"),
        ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "", "through WMI"),
        ("C:\\Windows\\System32\\wsmprovhost.exe", "", "PowerShell remoting"),
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k DcomLaunch -p", "DCOM"),
        ("C:\\Program Files\\Office\\EXCEL.EXE", "excel.exe /automation -Embedding", "DCOM"),
        ("C:\\Program Files\\Office\\WINWORD.EXE", "winword.exe doc.docm", "Office application"),
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule", "task"),
    ],
)
def test_known_launchers_are_named(parent, parent_cmd, expected):
    assert expected in launch_context(_event(parent, parent_cmd))


def test_shell_under_services_mentions_remote_service_execution():
    services = "C:\\Windows\\System32\\services.exe"
    assert "remote service execution" in launch_context(_event(services))
    svc_binary = "C:\\Program Files\\Vendor\\agent.exe"
    assert "remote service" not in launch_context(_event(services, image=svc_binary))


@pytest.mark.parametrize(
    "parent",
    [
        None,
        "C:\\Windows\\explorer.exe",
        "C:\\Users\\bob\\Desktop\\services.exe",  # masquerading: not the real SCM path
    ],
)
def test_ordinary_or_spoofed_parents_give_no_context(parent):
    assert launch_context(_event(parent)) is None


def test_context_goes_into_the_search_query_and_the_prompt():
    event = _event("C:\\Windows\\System32\\services.exe")
    alert = Alert(alert_id="a-1", detection_name="t", severity="high", events=[event])
    assert enrichment_query(alert).startswith("Launch context: started by services.exe")
    assert "## LAUNCH CONTEXT events[0]" in build_user_message(alert, [], [])
