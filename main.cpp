#include "pa.h"

int main() {
    if (!IsRunningAsAdmin()) {
        std::wcout << L"ERROR: Run this program as Administrator!\n";
        std::wcout << L"Press any key to exit...";
        _getch();
        return 1;
    }

    try {
        Rw9M_ProcAnalyzer a;
        a.VStartAnalysis();
    }
    catch (...) {
        return 1;
    }
    return 0;
}
