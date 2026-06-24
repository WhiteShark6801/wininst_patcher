// Common.h - Shared types, helpers, and Win32 includes
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>

// Architecture detected from media root
enum class Arch {
    X86,    // I386 only
    AMD64,  // AMD64 + I386 (WOW)
    IA64    // IA64  + I386 (WOW)
};

// Returns the literal subdirectory name on the media for a given arch
inline const wchar_t* ArchDirName(Arch a) {
    switch (a) {
        case Arch::X86:   return L"I386";
        case Arch::AMD64: return L"AMD64";
        case Arch::IA64:  return L"IA64";
    }
    return L"I386";
}

// Logging
void LogInfo (const wchar_t* fmt, ...);
void LogWarn (const wchar_t* fmt, ...);
void LogError(const wchar_t* fmt, ...);
void LogDebug(const wchar_t* fmt, ...);
void SetVerbose(bool v);

// Open a logfile next to the executable, named with a timestamp. Every
// subsequent LogXxx call also writes to it, flushed after every line so the
// file is useful even after a crash. Returns the path on success, empty on
// failure.
std::wstring OpenLogFile();
void CloseLogFile();

// Path helpers
std::wstring PathJoin(const std::wstring& a, const std::wstring& b);
std::wstring PathJoin(const std::wstring& a, const std::wstring& b, const std::wstring& c);
std::wstring GetFileNameFromPath(const std::wstring& full);
std::wstring GetDirFromPath(const std::wstring& full);
std::wstring ToLower(std::wstring s);
std::wstring ToUpper(std::wstring s);
bool         EndsWithI(const std::wstring& s, const std::wstring& suffix);
bool         StartsWithI(const std::wstring& s, const std::wstring& prefix);

// FS helpers
bool DirExists (const std::wstring& path);
bool FileExists(const std::wstring& path);
bool MakeDirs  (const std::wstring& path);   // mkdir -p
bool RemoveTree(const std::wstring& path);   // rm -rf
bool CopyFileNoOverwrite(const std::wstring& src, const std::wstring& dst);
bool CopyFileForce      (const std::wstring& src, const std::wstring& dst);
bool CopyTreeNoOverwrite(const std::wstring& src, const std::wstring& dst);
bool CopyTreeForce      (const std::wstring& src, const std::wstring& dst);

// Iterate files matching a set of extensions (case-insensitive) in a single dir.
// extensions e.g. {L".dl_", L".ex_"}. Pass empty vector to get all files.
std::vector<std::wstring> ListFilesByExt(const std::wstring& dir,
                                         const std::vector<std::wstring>& exts);

// Clear the read-only / hidden / system attributes on every file in `dir`
// (non-recursive). No-op if the directory doesn't exist.
void ClearReadOnlyInDir(const std::wstring& dir);

// Run a command line, wait for completion, return exit code (or -1 on failure)
int RunCommand(const std::wstring& cmdLine, const std::wstring& workingDir = L"");

// Prompt
std::wstring Prompt(const wchar_t* msg);

// Returns the absolute directory containing the running executable
// (no trailing separator). Falls back to "." on failure.
std::wstring GetExeDir();
