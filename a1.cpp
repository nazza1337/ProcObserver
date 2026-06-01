#include "pa.h"
bool Rw9M_ProcAnalyzer::W8x4_ElevatePrivileges() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    DWORD dwError = GetLastError();
    CloseHandle(hToken);

    if (!result || dwError != ERROR_SUCCESS) {
        std::wcout << L"\x1b[1;31mFailed to enable debug privileges. Run as Administrator!\x1b[0m\n";
        return false;
    }
    return true;
}

std::wstring Rw9M_ProcAnalyzer::P9x2(DWORD p) {
    HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p);
    if (!hP) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) return L"ACCESS_DENIED";
        if (e == ERROR_INVALID_PARAMETER) return L"INVALID_PID";
        return L"LOCKED_ACCESS";
    }
    HANDLE hT = NULL;
    if (!OpenProcessToken(hP, TOKEN_QUERY, &hT)) {
        CloseHandle(hP);
        return L"TOKEN_BLOCKED";
    }

    DWORD s = 0;
    GetTokenInformation(hT, TokenUser, NULL, 0, &s);
    if (s == 0) {
        CloseHandle(hT);
        CloseHandle(hP);
        return L"TOKEN_EMPTY";
    }

    std::vector<BYTE> b(s);
    PTOKEN_USER u = reinterpret_cast<PTOKEN_USER>(b.data());
    if (!GetTokenInformation(hT, TokenUser, u, s, &s)) {
        CloseHandle(hT);
        CloseHandle(hP);
        return L"TOKEN_FAIL";
    }

    WCHAR a[c_nBuf] = { 0 }, d[c_nDom] = { 0 };
    DWORD ca = c_nBuf, cd = c_nDom;
    SID_NAME_USE x;
    if (!LookupAccountSidW(NULL, u->User.Sid, a, &ca, d, &cd, &x)) {
        CloseHandle(hT);
        CloseHandle(hP);
        return L"SID_LOOKUP_FAIL";
    }

    CloseHandle(hT);
    CloseHandle(hP);
    return std::wstring(d) + L"\\" + a;
}

std::wstring Rw9M_ProcAnalyzer::K3m7(DWORD p) {
    HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p);
    if (!hP) {
        DWORD e = GetLastError();
        switch (e) {
        case ERROR_ACCESS_DENIED: return L"GUARDED";
        case ERROR_INVALID_PARAMETER: return L"INVALID";
        default: return L"VANISHED";
        }
    }
    DWORD x = 0;
    BOOL r = GetExitCodeProcess(hP, &x);
    CloseHandle(hP);
    if (!r) return L"UNREADABLE";
    return (x == STILL_ACTIVE) ? L"ACTIVE" : L"DORMANT";
}

void Rw9M_ProcAnalyzer::W5t9(DWORD p, std::vector<std::wstring>& o) {
    o.clear();

    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                o.push_back(me32.szExePath);
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);

        if (!o.empty()) {
            return;
        }
    }

    //EnumProcessModules
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                WCHAR szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                    o.push_back(szModName);
                }
            }
        }
        CloseHandle(hProcess);

        if (!o.empty()) {
            return;
        }
    }

    //dlya secured proccesov
    HANDLE hProcess2 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p);
    if (hProcess2) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
                HANDLE, DWORD, PVOID, ULONG, PULONG
                );

            auto NtQueryInformationProcess = (pNtQueryInformationProcess)
                GetProcAddress(ntdll, "NtQueryInformationProcess");

            if (NtQueryInformationProcess) {
                PROCESS_BASIC_INFORMATION pbi = { 0 };
                ULONG returnLength = 0;

                if (NtQueryInformationProcess(hProcess2, 0, &pbi, sizeof(pbi), &returnLength) == 0
                    && pbi.PebBaseAddress) {

                    PEB peb = { 0 };
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess2, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)
                        && bytesRead == sizeof(peb)) {

                        PEB_LDR_DATA ldr = { 0 };
                        if (ReadProcessMemory(hProcess2, peb.Ldr, &ldr, sizeof(ldr), &bytesRead)
                            && bytesRead == sizeof(ldr)) {

                            LIST_ENTRY* head = ldr.InMemoryOrderModuleList.Flink;
                            LIST_ENTRY* current = head;
                            int safetyCounter = 0;

                            do {
                                LDR_DATA_TABLE_ENTRY entry = { 0 };
                                PLDR_DATA_TABLE_ENTRY entryAddr = CONTAINING_RECORD(
                                    current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                                if (ReadProcessMemory(hProcess2, entryAddr, &entry, sizeof(entry), &bytesRead)
                                    && bytesRead == sizeof(entry)) {

                                    if (entry.FullDllName.Buffer && entry.FullDllName.Length > 0
                                        && entry.FullDllName.Length < (MAX_PATH * sizeof(WCHAR))) {

                                        std::vector<WCHAR> dllPath(entry.FullDllName.Length / sizeof(WCHAR) + 1);
                                        if (ReadProcessMemory(hProcess2, entry.FullDllName.Buffer,
                                            dllPath.data(), entry.FullDllName.Length, &bytesRead)) {
                                            dllPath[entry.FullDllName.Length / sizeof(WCHAR)] = L'\0';
                                            o.push_back(dllPath.data());
                                        }
                                    }
                                }

                                current = entry.InMemoryOrderLinks.Flink;
                                safetyCounter++;

                            } while (current != head && safetyCounter < 1000);
                        }
                    }
                }
            }
        }
        CloseHandle(hProcess2);
    }
}

void Rw9M_ProcAnalyzer::J2h4(wchar_t c, int l) {
    std::wcout << L"\x1b[1;36m" << std::wstring(l, c) << L"\x1b[0m\n";
}

std::wstring Rw9M_ProcAnalyzer::L8q1(const std::wstring& s) {
    if (s == L"ACTIVE") return L"\x1b[1;32m";
    if (s == L"DORMANT") return L"\x1b[1;33m";
    if (s == L"GUARDED") return L"\x1b[1;31m";
    if (s == L"ACCESS_DENIED") return L"\x1b[1;35m";
    return L"\x1b[1;30m";
}

void Rw9M_ProcAnalyzer::Y6f0() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::locale::global(std::locale(".UTF-8"));
    std::wcout.imbue(std::locale());
    std::wcin.imbue(std::locale());
}

void Rw9M_ProcAnalyzer::VScanAllProcesses() {
    m_vProcTable.clear();
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) {
        std::wcerr << L"\x1b[1;31mSnapshot failed\x1b[0m\n";
        return;
    }

    PROCESSENTRY32W p;
    p.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(s, &p)) {
        CloseHandle(s);
        return;
    }

    do {
        Xc3V_ProcEntry e;
        e.nPid = p.th32ProcessID;
        e.sExeName = p.szExeFile;
        e.sUserName = P9x2(p.th32ProcessID);
        e.sExecState = K3m7(p.th32ProcessID);

        
        W5t9(p.th32ProcessID, e.vDllList);

        
        if (e.vDllList.empty()) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.th32ProcessID);
            if (hProcess) {
                CloseHandle(hProcess);
                W5t9(p.th32ProcessID, e.vDllList); 
            }
        }

        m_vProcTable.push_back(std::move(e));
    } while (Process32NextW(s, &p));

    CloseHandle(s);
}

void Rw9M_ProcAnalyzer::VDisplayMainTable() {
    system("cls");
    std::wcout << L"\x1b[1;37;44m" << L" PROCESS OBSERVER - READ ONLY MODE " << L"\x1b[0m\n\n";
    J2h4(L'═', 105);
    std::wcout << std::left << L"\x1b[1;33m" << std::setw(8) << L"PID"
        << std::setw(14) << L"STATE"
        << std::setw(32) << L"USER CONTEXT"
        << L"IMAGE NAME\x1b[0m\n";
    J2h4(L'═', 105);

    for (const auto& r : m_vProcTable) {
        std::wstring c = L8q1(r.sExecState);
        std::wcout << std::left << std::setw(8) << r.nPid
            << c << std::setw(14) << r.sExecState << L"\x1b[0m"
            << std::setw(32) << r.sUserName.substr(0, 31)
            << r.sExeName << L"\n";
    }

    J2h4(L'═', 105);
    std::wcout << L"\n\x1b[1;37mTotal processes: " << m_vProcTable.size() << L"\x1b[0m\n";
}

void Rw9M_ProcAnalyzer::VInspectProcessModules(DWORD p) {
    system("cls");
    auto i = std::find_if(m_vProcTable.begin(), m_vProcTable.end(),
        [p](const Xc3V_ProcEntry& e) { return e.nPid == p; });

    if (i == m_vProcTable.end()) {
        std::wcout << L"\x1b[1;31mPID " << p << L" not found\x1b[0m\n";
        std::wcout << L"Press [ESC] to return...";
        while (_getch() != 27) {}
        return;
    }

    const auto& e = *i;
    std::wcout << L"\x1b[1;37;45m" << L" DLL INSPECTOR " << L"\x1b[0m\n\n";
    std::wcout << L"\x1b[1;36mPID:\x1b[0m " << e.nPid
        << L"\n\x1b[1;36mName:\x1b[0m " << e.sExeName
        << L"\n\x1b[1;36mState:\x1b[0m " << e.sExecState
        << L"\n\x1b[1;36mUser:\x1b[0m " << e.sUserName
        << L"\n\x1b[1;36mLoaded modules:\x1b[0m " << e.vDllList.size() << L"\n\n";

    if (e.vDllList.empty()) {
        std::wcout << L"\x1b[1;33mNo modules loaded or access denied\x1b[0m\n";
    }
    else {
        J2h4(L'─', 100);
        for (size_t j = 0; j < e.vDllList.size(); ++j) {
            const std::wstring& m = e.vDllList[j];
            size_t d = m.find_last_of(L'\\');
            std::wstring h = (d != std::wstring::npos) ? m.substr(d + 1) : m;
            std::wcout << L"\x1b[1;32m[" << std::setw(3) << std::right << j << L"]\x1b[0m "
                << h << L"\n     \x1b[1;30m" << m << L"\x1b[0m\n";
        }
        J2h4(L'─', 100);
    }

    std::wcout << L"\n\x1b[1;37m[ESC] Return to process list | [R] Rescan modules\x1b[0m\n";

    while (true) {
        int key = _getch();
        if (key == 27) break; // ESC
        if (key == 'r' || key == 'R') {
          
            std::vector<std::wstring> newModules;
            W5t9(p, newModules);

            
            auto it = std::find_if(m_vProcTable.begin(), m_vProcTable.end(),
                [p](const Xc3V_ProcEntry& entry) { return entry.nPid == p; });
            if (it != m_vProcTable.end()) {
                it->vDllList = std::move(newModules);
            }

            
            VInspectProcessModules(p);
            return;
        }
    }
}

void Rw9M_ProcAnalyzer::VStartAnalysis() {
    Y6f0();

    // Attempt privilege escalation
    if (W8x4_ElevatePrivileges()) {
        std::wcout << L"\x1b[1;32mDebug privileges enabled\x1b[0m\n";
    }

    VScanAllProcesses();
    VDisplayMainTable();

    std::wcout << L"\n\x1b[1;37mCommands: [PID + Enter] Inspect DLLs | [R] Rescan | [ESC] Exit\x1b[0m\n\x1b[1;37m>\x1b[0m ";

    std::wstring input;
    while (true) {
        if (_kbhit()) {
            int key = _getch();

           
            if (key == 27) {
                break;
            }

            if (key == 'r' || key == 'R') {
                input.clear();
                VScanAllProcesses();
                VDisplayMainTable();
                std::wcout << L"\n\x1b[1;37mCommands: [PID + Enter] Inspect DLLs | [R] Rescan | [ESC] Exit\x1b[0m\n\x1b[1;37m>\x1b[0m ";
                continue;
            }

            if (key == '\r' || key == '\n') {
                if (!input.empty()) {
                    try {
                        size_t o = 0;
                        DWORD pid = std::stoul(input, &o);
                        if (o == input.length()) {
                            VInspectProcessModules(pid);
                            VDisplayMainTable();
                        }
                        else {
                            std::wcout << L"\n\x1b[1;31mInvalid PID format\x1b[0m\n";
                        }
                    }
                    catch (...) {
                        std::wcout << L"\n\x1b[1;31mInvalid input\x1b[0m\n";
                    }
                }
                input.clear();
                std::wcout << L"\n\x1b[1;37mCommands: [PID + Enter] Inspect DLLs | [R] Rescan | [ESC] Exit\x1b[0m\n\x1b[1;37m>\x1b[0m ";
                continue;
            }

            
            if (key == '\b' || key == 127) {
                if (!input.empty()) {
                    input.pop_back();
                    std::wcout << L"\b \b";
                }
                continue;
            }

            
            if (key >= '0' && key <= '9') {
                input += (wchar_t)key;
                std::wcout << (wchar_t)key;
            }
        }
        Sleep(10);
    }
}
//tut doxuya noolet power nt admin0
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}
