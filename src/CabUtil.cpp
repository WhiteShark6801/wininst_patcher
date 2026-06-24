// CabUtil.cpp
#include "CabUtil.h"

#include <fstream>

bool ExtractCab(const std::wstring& cabFile, const std::wstring& outDir) {
    if (!FileExists(cabFile)) {
        LogWarn(L"CAB not found: %s", cabFile.c_str());
        return false;
    }
    if (!MakeDirs(outDir)) return false;

    LogInfo(L"Extracting %s -> %s", cabFile.c_str(), outDir.c_str());
    // expand.exe -R -F:* "cab" "dst"
    std::wstring cmd = L"expand.exe -R -F:* \"" + cabFile + L"\" \"" + outDir + L"\"";
    int rc = RunCommand(cmd);
    if (rc != 0) {
        LogError(L"expand.exe failed (rc=%d) for %s", rc, cabFile.c_str());
        return false;
    }
    return true;
}

// Replace the last char of the extension with '_'. e.g. ".dll" -> ".dl_"
static std::wstring CompressedExt(const std::wstring& filename) {
    size_t dot = filename.find_last_of(L'.');
    if (dot == std::wstring::npos) return filename + L"_";
    std::wstring stem = filename.substr(0, dot);
    std::wstring ext  = filename.substr(dot);   // includes "."
    if (ext.size() < 2) return filename + L"_";
    ext[ext.size() - 1] = L'_';
    return stem + ext;
}

bool CompressFolderPerFile(const std::wstring& srcDir, const std::wstring& dstDir) {
    if (!DirExists(srcDir)) {
        LogWarn(L"CompressFolderPerFile: source missing: %s", srcDir.c_str());
        return true; // nothing to do
    }
    if (!MakeDirs(dstDir)) return false;

    auto files = ListFilesByExt(srcDir, {});  // all files
    bool allOk = true;

    for (const auto& src : files) {
        std::wstring base = GetFileNameFromPath(src);
        std::wstring outName = CompressedExt(base);
        std::wstring outPath = PathJoin(dstDir, outName);

        // makecab "src" "dst.dl_"
        std::wstring cmd = L"makecab.exe \"" + src + L"\" \"" + outPath + L"\"";
        LogDebug(L"  makecab %s -> %s", base.c_str(), outName.c_str());
        int rc = RunCommand(cmd);
        if (rc != 0) {
            LogError(L"makecab failed (rc=%d) for %s", rc, src.c_str());
            allOk = false;
        }
    }
    return allOk;
}

// Build a single CAB containing every top-level file in srcDir.
//
// Strategy: write a DDF (Diamond Directive File) and run `makecab /F`.
// This is the canonical way to build a multi-file CAB with makecab and works
// on plain Windows installs without the SDK (cabarc.exe is not always there;
// makecab.exe always is).
bool BuildCab(const std::wstring& srcDir, const std::wstring& cabPath) {
    if (!DirExists(srcDir)) {
        LogWarn(L"BuildCab: source missing: %s", srcDir.c_str());
        return false;
    }

    auto files = ListFilesByExt(srcDir, {});
    if (files.empty()) {
        LogWarn(L"BuildCab: no files to pack in %s", srcDir.c_str());
        return false;
    }

    std::wstring cabName = GetFileNameFromPath(cabPath);
    std::wstring cabDir  = GetDirFromPath(cabPath);
    if (cabDir.empty()) cabDir = L".";
    MakeDirs(cabDir);

    // Use a per-build scratch dir so concurrent runs don't collide.
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring scratch = PathJoin(tmp, L"wininst_makecab_" +
                                          std::to_wstring(GetCurrentProcessId()) + L"_" +
                                          std::to_wstring(GetTickCount()));
    MakeDirs(scratch);

    std::wstring ddfPath = PathJoin(scratch, L"build.ddf");

    // Write DDF
    {
        std::wofstream f(ddfPath);
        if (!f.is_open()) {
            LogError(L"Cannot write DDF: %s", ddfPath.c_str());
            return false;
        }
        f << L".OPTION EXPLICIT\r\n";
        f << L".Set CabinetNameTemplate=" << cabName << L"\r\n";
        f << L".Set DiskDirectory1=" << cabDir << L"\r\n";
        f << L".Set Cabinet=ON\r\n";
        f << L".Set Compress=ON\r\n";
        f << L".Set CompressionType=MSZIP\r\n";
        f << L".Set MaxDiskSize=0\r\n";
        f << L".Set UniqueFiles=OFF\r\n";
        // Each file:  "src"  destname
        for (const auto& s : files) {
            std::wstring base = GetFileNameFromPath(s);
            f << L"\"" << s << L"\" \"" << base << L"\"\r\n";
        }
    }

    LogInfo(L"Building %s (%zu files)...", cabPath.c_str(), files.size());
    std::wstring cmd = L"makecab.exe /F \"" + ddfPath + L"\"";
    int rc = RunCommand(cmd, scratch);

    // makecab leaves setup.inf + setup.rpt next to the cab; clean them up.
    DeleteFileW(PathJoin(cabDir, L"setup.inf").c_str());
    DeleteFileW(PathJoin(cabDir, L"setup.rpt").c_str());
    RemoveTree(scratch);

    if (rc != 0) {
        LogError(L"makecab /F failed (rc=%d)", rc);
        return false;
    }
    return FileExists(cabPath);
}
