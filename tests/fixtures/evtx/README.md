# EVTX fixtures

Real Windows 10 event logs extracted from the `DFA_SP2020_Windows.E01`
training disk image (`Windows/System32/winevt/Logs`). They exercise the
parser, search, decoding, descriptions and hunts against genuine data:

| File | Events | Notes |
|---|---|---|
| `security.evtx` | 10,667 | logons, account/group changes, crypto ops, 4616 |
| `application.evtx` | 1,934 | mixed third-party providers, no templates |
| `system.evtx` | 1,416 | services (7045/7040), unresolved `%%` HRESULTs |
| `setup.evtx` | 24 | servicing (UserData, not EventData) |
| `hardware-events.evtx`, `internet-explorer.evtx`, `key-management-service.evtx` | 0 | empty logs: header + one empty chunk |

Counts asserted in `tests/` are snapshots of this data — if a test fails
after a parser upgrade, check whether the behaviour change is intended.
