# Process Observer — Read-Only Mode

A console-based Windows utility for auditing and monitoring active processes. Provides detailed information on each process, including loaded modules, user context, and execution state. The tool operates strictly in read-only mode and never modifies target processes.

---

## Features

### Process Table (Main View)

On launch, the program scans all running processes and displays:

| Column         | Description                                        |
|----------------|----------------------------------------------------|
| **PID**        | Process identifier                                 |
| **STATE**      | Execution state (see below)                        |
| **USER CONTEXT** | Resolved user account (`DOMAIN\User` format)     |
| **IMAGE NAME** | Executable file name                               |

#### Process States

| Value          | Color  | Meaning                                                      |
|----------------|--------|--------------------------------------------------------------|
| `ACTIVE`       | Green  | Process is running (`STILL_ACTIVE` exit code)                |
| `DORMANT`      | Yellow | Process has terminated but the object still exists           |
| `GUARDED`      | Red    | Access denied — state cannot be determined                   |
| `VANISHED`     | Grey   | Process no longer exists (failed to open by PID)             |
| `UNREADABLE`   | Grey   | Failed to retrieve exit code                                 |
| `INVALID`      | Grey   | Invalid PID                                                  |

#### User Context Values

| Value            | Meaning                                              |
|------------------|------------------------------------------------------|
| `DOMAIN\User`    | Successfully resolved via process token              |
| `LOCKED_ACCESS`  | Could not open process with query permissions        |
| `TOKEN_BLOCKED`  | Could not open process token                         |
| `TOKEN_FAIL`     | Token information query failed                       |

---

### DLL Inspector (PID-Specific View)

Enter a PID to inspect loaded modules of that process. Displays:

- PID, image name, state, and user context (from the cached scan);
- Total number of loaded modules;
- Indexed list of DLLs with short file name and full path.

Press **ESC** to return to the main process table.

---

## Commands

| Input              | Action                                                   |
|--------------------|----------------------------------------------------------|
| `PID + Enter`      | Open DLL inspector for the specified process             |
| `0 + Enter`        | Rescan and refresh the process table                     |
| `Enter` (empty)    | Exit the program                                         |

---

## Technical Notes

- Processes are enumerated via a one-time snapshot (`CreateToolhelp32Snapshot`). Refresh is manual (command `0`).
- DLL enumeration uses a separate module snapshot, triggered only when inspecting a specific PID.
- User resolution is performed via the process access token: opening the token, extracting the SID, and calling `LookupAccountSidW`.
- All failure paths are handled and surfaced as human-readable labels in the UI.
- Console uses ANSI/VT100 escape sequences for coloring. Requires Windows 10+ (or compatible terminal).

---

## Build Dependencies

- **OS**: Windows XP or later
- **Compiler**: MSVC with C++11 support
- **Libraries**: `psapi.lib` (linked via `#pragma comment`)

---

## Limitations

- Full information is only available for processes the current user can access. Protected/system processes may appear as `GUARDED` or `LOCKED_ACCESS`.
- 32-bit modules inside 64-bit processes (and vice versa) may not be enumerated depending on the bitness of this tool.
- The process table reflects a point-in-time snapshot; no real-time monitoring is performed.
