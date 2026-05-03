#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <conio.h>
#include <algorithm>
#include <stdexcept>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

struct Xc3V_ProcEntry {
    DWORD nPid;
    std::wstring sExeName;
    std::wstring sUserName;
    std::wstring sExecState;
    std::vector<std::wstring> vDllList;
};

class Rw9M_ProcAnalyzer {
private:
    std::vector<Xc3V_ProcEntry> m_vProcTable;
    static constexpr size_t c_nBuf = 256;
    static constexpr size_t c_nDom = 256;

    std::wstring P9x2(DWORD p) {
        HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p);
        if (!hP) {
            DWORD e = GetLastError();
            if (e == ERROR_ACCESS_DENIED) return L"ACCESS_DENIED";
            if (e == ERROR_INVALID_PARAMETER) return L"INVALID_PID";
            return L"LOCKED_ACCESS";
        }
        HANDLE hT = NULL;
        if (!OpenProcessToken(hP, TOKEN_QUERY, &hT)) { CloseHandle(hP); return L"TOKEN_BLOCKED"; }
        DWORD s = 0;
        GetTokenInformation(hT, TokenUser, NULL, 0, &s);
        if (s == 0) { CloseHandle(hT); CloseHandle(hP); return L"TOKEN_EMPTY"; }
        std::vector<BYTE> b(s);
        PTOKEN_USER u = reinterpret_cast<PTOKEN_USER>(b.data());
        if (!GetTokenInformation(hT, TokenUser, u, s, &s)) { CloseHandle(hT); CloseHandle(hP); return L"TOKEN_FAIL"; }
        WCHAR a[c_nBuf] = { 0 }, d[c_nDom] = { 0 };
        DWORD ca = c_nBuf, cd = c_nDom;
        SID_NAME_USE x;
        if (!LookupAccountSidW(NULL, u->User.Sid, a, &ca, d, &cd, &x)) { CloseHandle(hT); CloseHandle(hP); return L"SID_LOOKUP_FAIL"; }
        CloseHandle(hT); CloseHandle(hP);
        return std::wstring(d) + L"\\" + a;
    }

    std::wstring K3m7(DWORD p) {
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

    void W5t9(DWORD p, std::vector<std::wstring>& o) {
        o.clear();
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
        if (s == INVALID_HANDLE_VALUE) return;
        MODULEENTRY32W m;
        m.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(s, &m)) { do { o.push_back(m.szExePath); } while (Module32NextW(s, &m)); }
        CloseHandle(s);
    }

    void J2h4(wchar_t c, int l) {
        std::wcout << L"\x1b[1;36m" << std::wstring(l, c) << L"\x1b[0m\n";
    }

    std::wstring L8q1(const std::wstring& s) {
        if (s == L"ACTIVE") return L"\x1b[1;32m";
        if (s == L"DORMANT") return L"\x1b[1;33m";
        if (s == L"GUARDED") return L"\x1b[1;31m";
        if (s == L"ACCESS_DENIED") return L"\x1b[1;35m";
        return L"\x1b[1;30m";
    }

    void Y6f0() {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        std::locale::global(std::locale(".UTF-8"));
        std::wcout.imbue(std::locale());
        std::wcin.imbue(std::locale());
    }

public:
    void VScanAllProcesses() {
        m_vProcTable.clear();
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (s == INVALID_HANDLE_VALUE) { std::wcerr << L"\x1b[1;31mSnapshot failed\x1b[0m\n"; return; }
        PROCESSENTRY32W p;
        p.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(s, &p)) { CloseHandle(s); return; }
        do {
            Xc3V_ProcEntry e;
            e.nPid = p.th32ProcessID;
            e.sExeName = p.szExeFile;
            e.sUserName = P9x2(p.th32ProcessID);
            e.sExecState = K3m7(p.th32ProcessID);
            W5t9(p.th32ProcessID, e.vDllList);
            m_vProcTable.push_back(std::move(e));
        } while (Process32NextW(s, &p));
        CloseHandle(s);
    }

    void VDisplayMainTable() {
        system("cls");
        std::wcout << L"\x1b[1;37;44m" << L" PROCESS OBSERVER - READ ONLY MODE " << L"\x1b[0m\n\n";
        J2h4(L'═', 105);
        std::wcout << std::left << L"\x1b[1;33m" << std::setw(8) << L"PID" << std::setw(14) << L"STATE" << std::setw(32) << L"USER CONTEXT" << L"IMAGE NAME\x1b[0m\n";
        J2h4(L'═', 105);
        for (const auto& r : m_vProcTable) {
            std::wstring c = L8q1(r.sExecState);
            std::wcout << std::left << std::setw(8) << r.nPid << c << std::setw(14) << r.sExecState << L"\x1b[0m" << std::setw(32) << r.sUserName.substr(0, 31) << r.sExeName << L"\n";
        }
        J2h4(L'═', 105);
        std::wcout << L"\n\x1b[1;37mTotal processes: " << m_vProcTable.size() << L"\x1b[0m\n";
    }

    void VInspectProcessModules(DWORD p) {
        system("cls");
        auto i = std::find_if(m_vProcTable.begin(), m_vProcTable.end(), [p](const Xc3V_ProcEntry& e) { return e.nPid == p; });
        if (i == m_vProcTable.end()) { std::wcout << L"\x1b[1;31mPID " << p << L" not found\x1b[0m\n"; std::wcout << L"Press any key..."; _getch(); return; }
        const auto& e = *i;
        std::wcout << L"\x1b[1;37;45m" << L" DLL INSPECTOR " << L"\x1b[0m\n\n";
        std::wcout << L"\x1b[1;36mPID:\x1b[0m " << e.nPid << L"\n\x1b[1;36mName:\x1b[0m " << e.sExeName << L"\n\x1b[1;36mState:\x1b[0m " << e.sExecState << L"\n\x1b[1;36mUser:\x1b[0m " << e.sUserName << L"\n\x1b[1;36mLoaded modules:\x1b[0m " << e.vDllList.size() << L"\n\n";
        if (e.vDllList.empty()) { std::wcout << L"\x1b[1;33mNo modules loaded or access denied\x1b[0m\n"; }
        else {
            J2h4(L'─', 100);
            for (size_t j = 0; j < e.vDllList.size(); ++j) {
                const std::wstring& m = e.vDllList[j];
                size_t d = m.find_last_of(L'\\');
                std::wstring h = (d != std::wstring::npos) ? m.substr(d + 1) : m;
                std::wcout << L"\x1b[1;32m[" << std::setw(3) << std::right << j << L"]\x1b[0m " << h << L"\n     \x1b[1;30m" << m << L"\x1b[0m\n";
            }
            J2h4(L'─', 100);
        }
        std::wcout << L"\n\x1b[1;37m[ESC] Return to process list\x1b[0m\n";
        while (_getch() != 27) {}
    }

    void VStartAnalysis() {
        Y6f0();
        VScanAllProcesses();
        VDisplayMainTable();
        std::wcout << L"\n\x1b[1;37mCommands: [PID + Enter] Inspect DLLs | [0] Rescan | [Enter] Exit\x1b[0m\n\x1b[1;37m>\x1b[0m ";
        std::wstring z;
        while (std::getline(std::wcin, z)) {
            if (z.empty()) break;
            try {
                size_t o = 0;
                DWORD p = std::stoul(z, &o);
                if (o != z.length()) throw std::invalid_argument("");
                if (p == 0) { VScanAllProcesses(); VDisplayMainTable(); }
                else { VInspectProcessModules(p); VDisplayMainTable(); }
            }
            catch (...) { std::wcout << L"\x1b[1;31mInvalid input\x1b[0m\n"; }
            std::wcout << L"\n\x1b[1;37mCommands: [PID + Enter] Inspect DLLs | [0] Rescan | [Enter] Exit\x1b[0m\n\x1b[1;37m>\x1b[0m ";
        }
    }
};

int main() {
    try { Rw9M_ProcAnalyzer a; a.VStartAnalysis(); }
    catch (...) { return 1; }
    return 0;
}
