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
    bool postBuildOnly = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--verbose") == 0)
            verbose = true;
        else if (wcscmp(argv[i], L"-p") == 0 || wcscmp(argv[i], L"--postbuild-only") == 0)
            postBuildOnly = true;
        else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            wprintf(
              L"wininst_patcher - cross-stamp Windows 2000/XP/2003 install media\n"
              L"\n"
              L"Usage: wininst_patcher [-v] [-p]\n"
              L"\n"
              L"Options:\n"
              L"  -v, --verbose       Verbose logging.\n"
              L"  -p, --postbuild-only\n"
              L"                      Finish an existing output folder instead of\n"
              L"                      patching from scratch. Steps 3-10 are skipped;\n"
              L"                      the Base media text files (*.inf, *.in_, *.ca_,\n"
              L"                      *.cat, *.sif) are refreshed from the Base ISO\n"
              L"                      and the post-step-10 fixups are applied. The\n"
              L"                      output folder must already exist and be writable,\n"
              L"                      typically the output folder of a failed run.\n"
              L"                      Useful when a run failed late and you do not\n"
              L"                      want to start over.\n"
              L"\n"
              L"You will be prompted for:\n"
              L"  1. Base ISO root        (target media to be patched)\n"
              L"  2. Resource ISO root    (donor media supplying resources)\n"
              L"  3. Output dir           (will hold the patched media tree)\n"
              L"  4. Mode (Safe/Full)\n"
              L"\n"
              L"  With -p, the Mode prompt is not shown.\n");
            return 0;
        }
    }
    SetVerbose(verbose);

    SetUnhandledExceptionFilter(CrashFlushFilter);
    std::atexit(CloseLogFile);

    std::wstring logPath = OpenLogFile();
    if (!logPath.empty())
        wprintf(L"Logging to: %s\n", logPath.c_str());

    bool ok = RunPipeline(postBuildOnly);

    wprintf(L"\n%s. Press any key to exit . . . ",
            ok ? L"Completed" : L"Finished with errors");
    fflush(stdout);
    // _getwch reads a single keystroke without echo; works on a console.
    (void)_getwch();
    wprintf(L"\n");

    CloseLogFile();
    return ok ? 0 : 1;
}
