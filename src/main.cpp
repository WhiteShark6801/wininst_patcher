// main.cpp
#include "Common.h"
#include "Pipeline.h"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <io.h>
#include <conio.h>

// Crash handler: just flush the logfile so partial state survives.
static LONG WINAPI CrashFlushFilter(EXCEPTION_POINTERS* /*ep*/) {
    LogError(L"Unhandled exception - terminating. Log was flushed.");
    CloseLogFile();
    return EXCEPTION_CONTINUE_SEARCH;  // let Windows show the usual crash UI
}

int wmain(int argc, wchar_t* argv[]) {
    // Make stdout/stderr Unicode-friendly so logs render correctly.
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    _setmode(_fileno(stdin),  _O_U16TEXT);

    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--verbose") == 0)
            verbose = true;
        else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            wprintf(
              L"wininst_patcher - cross-stamp Windows 2000/XP/2003 install media\n"
              L"\n"
              L"Usage: wininst_patcher [-v]\n"
              L"\n"
              L"You will be prompted for:\n"
              L"  1. Base ISO root        (target media to be patched)\n"
              L"  2. Resource ISO root    (donor media supplying resources)\n"
              L"  3. Output dir           (will hold the patched media tree)\n"
              L"  4. Mode (Attach/Replace)\n");
            return 0;
        }
    }
    SetVerbose(verbose);

    SetUnhandledExceptionFilter(CrashFlushFilter);
    std::atexit(CloseLogFile);

    std::wstring logPath = OpenLogFile();
    if (!logPath.empty())
        wprintf(L"Logging to: %s\n", logPath.c_str());

    bool ok = RunPipeline();

    wprintf(L"\n%s. Press any key to exit . . . ",
            ok ? L"Completed" : L"Finished with errors");
    fflush(stdout);
    // _getwch reads a single keystroke without echo; works on a console.
    (void)_getwch();
    wprintf(L"\n");

    CloseLogFile();
    return ok ? 0 : 1;
}
