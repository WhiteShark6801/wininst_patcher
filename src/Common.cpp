// Common.cpp - Shared utilities
#include "Common.h"

#include <cwchar>
#include <cstdarg>
#include <algorithm>
#include <shlwapi.h>
#include <shellapi.h>   // SHFileOperationW, SHFILEOPSTRUCTW, FO_DELETE, FOF_*

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

static bool g_verbose = false;
void SetVerbose(bool v) { g_verbose = v; }

// File-logging state
static FILE*       g_logFile = nullptr;
static std::wstring g_logPath;

std::wstring OpenLogFile() {
    if (g_logFile) return g_logPath;

    // Build a name: wininst_patcher-YYYYMMDD-HHMMSS.log next to the exe.
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t stamp[64];
    swprintf_s(stamp, L"wininst_patcher-%04u%02u%02u-%02u%02u%02u.log",
               st.wYear, st.wMonth,  st.wDay,
               st.wHour, st.wMinute, st.wSecond);

    std::wstring path = PathJoin(GetExeDir(), stamp);
    if (_wfopen_s(&g_logFile, path.c_str(), L"w, ccs=UTF-8") != 0 || !g_logFile) {
        g_logFile = nullptr;
        return L"";
    }
    setvbuf(g_logFile, nullptr, _IOLBF, 4096);   // line-buffered
    g_logPath = path;

    fwprintf(g_logFile, L"=== wininst_patcher log %04u-%02u-%02u %02u:%02u:%02u ===\n",
             st.wYear, st.wMonth,  st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    fflush(g_logFile);
    return g_logPath;
}

void CloseLogFile() {
    if (!g_logFile) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(g_logFile, L"=== closed %04u-%02u-%02u %02u:%02u:%02u ===\n",
             st.wYear, st.wMonth,  st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    fclose(g_logFile);
    g_logFile = nullptr;
    g_logPath.clear();
}

static void VLog(FILE* out, const wchar_t* tag, const wchar_t* fmt, va_list ap) {
    // Snapshot the args for re-use (vfwprintf consumes them).
    va_list ap2;
    va_copy(ap2, ap);

    fwprintf(out, L"[%s] ", tag);
    vfwprintf(out, fmt, ap);
    fwprintf(out, L"\n");
    fflush(out);

    if (g_logFile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fwprintf(g_logFile, L"%02u:%02u:%02u [%s] ",
                 st.wHour, st.wMinute, st.wSecond, tag);
        vfwprintf(g_logFile, fmt, ap2);
        fwprintf(g_logFile, L"\n");
        fflush(g_logFile);
    }
    va_end(ap2);
}

void LogInfo(const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    VLog(stdout, L"INFO ", fmt, ap);
    va_end(ap);
}
void LogWarn(const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    VLog(stdout, L"WARN ", fmt, ap);
    va_end(ap);
}
void LogError(const wchar_t* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    VLog(stderr, L"ERROR", fmt, ap);
    va_end(ap);
}
void LogDebug(const wchar_t* fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    VLog(stdout, L"DEBUG", fmt, ap);
    va_end(ap);
}

// ---- path helpers ----------------------------------------------------------

static bool HasTrailingSep(const std::wstring& s) {
    return !s.empty() && (s.back() == L'\\' || s.back() == L'/');
}

std::wstring PathJoin(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (HasTrailingSep(a)) return a + b;
    return a + L"\\" + b;
}

std::wstring PathJoin(const std::wstring& a, const std::wstring& b, const std::wstring& c) {
    return PathJoin(PathJoin(a, b), c);
}

std::wstring GetFileNameFromPath(const std::wstring& full) {
    size_t p = full.find_last_of(L"\\/");
    if (p == std::wstring::npos) return full;
    return full.substr(p + 1);
}

std::wstring GetDirFromPath(const std::wstring& full) {
    size_t p = full.find_last_of(L"\\/");
    if (p == std::wstring::npos) return L"";
    return full.substr(0, p);
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c){ return (wchar_t)::towlower(c); });
    return s;
}
std::wstring ToUpper(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c){ return (wchar_t)::towupper(c); });
    return s;
}

bool EndsWithI(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    return _wcsicmp(s.c_str() + (s.size() - suffix.size()), suffix.c_str()) == 0;
}
bool StartsWithI(const std::wstring& s, const std::wstring& prefix) {
    if (s.size() < prefix.size()) return false;
    return _wcsnicmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

// ---- filesystem ------------------------------------------------------------

bool DirExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
bool FileExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool MakeDirs(const std::wstring& path) {
    if (path.empty()) return false;
    if (DirExists(path)) return true;

    // Recurse on parent
    std::wstring parent = GetDirFromPath(path);
    if (!parent.empty() && parent != path) {
        // Don't recurse on a drive root like "C:"
        if (!(parent.size() == 2 && parent[1] == L':')) {
            if (!DirExists(parent) && !MakeDirs(parent)) return false;
        }
    }
    if (!CreateDirectoryW(path.c_str(), nullptr)) {
        DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS) {
            LogError(L"CreateDirectory failed (%lu): %s", e, path.c_str());
            return false;
        }
    }
    return true;
}

bool RemoveTree(const std::wstring& path) {
    if (!DirExists(path) && !FileExists(path)) return true;

    // SHFileOperation needs double-null-terminated input
    std::vector<wchar_t> buf(path.begin(), path.end());
    buf.push_back(L'\0');
    buf.push_back(L'\0');

    SHFILEOPSTRUCTW op = {};
    op.wFunc  = FO_DELETE;
    op.pFrom  = buf.data();
    op.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    int rc = SHFileOperationW(&op);
    if (rc != 0) {
        LogWarn(L"RemoveTree: SHFileOperation rc=%d for %s", rc, path.c_str());
        return false;
    }
    return true;
}

bool CopyFileForce(const std::wstring& src, const std::wstring& dst) {
    MakeDirs(GetDirFromPath(dst));
    // Clear read-only attribute on existing destination
    DWORD a = GetFileAttributesW(dst.c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY)) {
        SetFileAttributesW(dst.c_str(), a & ~FILE_ATTRIBUTE_READONLY);
    }
    if (!CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
        LogError(L"CopyFile failed (%lu): %s -> %s", GetLastError(), src.c_str(), dst.c_str());
        return false;
    }
    return true;
}

bool CopyFileNoOverwrite(const std::wstring& src, const std::wstring& dst) {
    if (FileExists(dst)) return true; // skip
    MakeDirs(GetDirFromPath(dst));
    if (!CopyFileW(src.c_str(), dst.c_str(), TRUE)) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_EXISTS) return true;
        LogError(L"CopyFile failed (%lu): %s -> %s", e, src.c_str(), dst.c_str());
        return false;
    }
    return true;
}

static bool CopyTreeImpl(const std::wstring& src, const std::wstring& dst, bool overwrite) {
    if (!DirExists(src)) {
        LogError(L"CopyTree: source not a directory: %s", src.c_str());
        return false;
    }
    MakeDirs(dst);

    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(src, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return true;

    bool ok = true;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring s = PathJoin(src, fd.cFileName);
        std::wstring d = PathJoin(dst, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!CopyTreeImpl(s, d, overwrite)) ok = false;
        } else {
            bool r = overwrite ? CopyFileForce(s, d) : CopyFileNoOverwrite(s, d);
            if (!r) ok = false;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}

bool CopyTreeForce      (const std::wstring& src, const std::wstring& dst) { return CopyTreeImpl(src, dst, true);  }
bool CopyTreeNoOverwrite(const std::wstring& src, const std::wstring& dst) { return CopyTreeImpl(src, dst, false); }

void ClearReadOnlyInDir(const std::wstring& dir) {
    if (!DirExists(dir)) return;
    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(dir, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        DWORD a = fd.dwFileAttributes;
        DWORD strip = (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        if (a & strip) {
            std::wstring full = PathJoin(dir, fd.cFileName);
            DWORD newAttrs = a & ~strip;
            if (newAttrs == 0) newAttrs = FILE_ATTRIBUTE_NORMAL;
            SetFileAttributesW(full.c_str(), newAttrs);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

std::vector<std::wstring> ListFilesByExt(const std::wstring& dir,
                                         const std::vector<std::wstring>& exts) {
    std::vector<std::wstring> out;
    if (!DirExists(dir)) return out;

    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(dir, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return out;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring name = fd.cFileName;
        if (exts.empty()) {
            out.push_back(PathJoin(dir, name));
            continue;
        }
        for (const auto& e : exts) {
            if (EndsWithI(name, e)) {
                out.push_back(PathJoin(dir, name));
                break;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return out;
}

// ---- exec ------------------------------------------------------------------

int RunCommand(const std::wstring& cmdLine, const std::wstring& workingDir) {
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    // CreateProcessW may modify the cmd line buffer, so make a writable copy
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    LPCWSTR cwd = workingDir.empty() ? nullptr : workingDir.c_str();
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr,
                             FALSE, CREATE_NO_WINDOW, nullptr, cwd, &si, &pi);
    if (!ok) {
        LogError(L"CreateProcess failed (%lu): %s", GetLastError(), cmdLine.c_str());
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)ec;
}

std::wstring Prompt(const wchar_t* msg) {
    fwprintf(stdout, L"%s", msg);
    fflush(stdout);
    wchar_t buf[1024] = {0};
    if (!fgetws(buf, _countof(buf), stdin)) return L"";
    std::wstring s = buf;
    // trim CR/LF and quotes/spaces
    while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' ||
                          s.back() == L' '  || s.back() == L'\t' ||
                          s.back() == L'"')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == L' ' || s[i] == L'\t' || s[i] == L'"')) i++;
    return s.substr(i);
}

std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return L".";
    std::wstring s(buf);
    std::wstring d = GetDirFromPath(s);
    return d.empty() ? std::wstring(L".") : d;
}
