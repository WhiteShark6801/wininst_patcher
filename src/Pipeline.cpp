// Pipeline.cpp - Steps 1-10 from the spec.
#include "Pipeline.h"
#include "ResourceExtract.h"
#include "ResourceUpdate.h"
#include "CabUtil.h"
#include "Language.h"
#include "HexPatch.h"
#include <imagehlp.h>
#include <utility>
#pragma comment(lib, "imagehlp.lib")

// (dir, oldName, newName) - records every rename so we can undo it later.
struct WRename {
    std::wstring dir;
    std::wstring fromName;  // e.g. waccess.cpl
    std::wstring toName;    // e.g. access.cpl
};

// Forward decls for helpers added at the bottom of this file.
static int  StripWPrefixInDir(const std::wstring& dir, std::vector<WRename>& log);
static void RestoreWPrefixes(const std::vector<WRename>& log);
static bool PostStep10Fixups(const std::wstring& outRoot, const std::wstring& iso1Root,
                             const std::wstring& iso2Root, Arch arch, Arch donorArch,
                             DWORD baseLang, DWORD newLang, bool replaceMode);


// ---------------------------------------------------------------------------
// Step 1 helpers : architecture + service pack detection
// ---------------------------------------------------------------------------

bool DetectArch(const std::wstring& mediaRoot, Arch& outArch) {
    std::wstring ia64  = PathJoin(mediaRoot, L"IA64");
    std::wstring amd64 = PathJoin(mediaRoot, L"AMD64");
    std::wstring i386  = PathJoin(mediaRoot, L"I386");

    if (DirExists(ia64))       { outArch = Arch::IA64;  return true; }
    if (DirExists(amd64))      { outArch = Arch::AMD64; return true; }
    if (DirExists(i386))       { outArch = Arch::X86;   return true; }

    LogError(L"No I386/AMD64/IA64 directory under %s", mediaRoot.c_str());
    return false;
}

bool HasServicePackCab(const std::wstring& mediaRoot,
                       std::wstring& outCabFile, int& outSpNum) {
    // Service pack CABs sit in the I386 directory on every NT-family install
    // medium I've seen.  Check both the root and I386.
    const wchar_t* candidates[] = { L"I386", L"AMD64", L"IA64", L"" };
    for (const wchar_t* sub : candidates) {
        std::wstring dir = (*sub) ? PathJoin(mediaRoot, sub) : mediaRoot;
        for (int n = 1; n <= 4; ++n) {
            std::wstring p = PathJoin(dir, L"SP" + std::to_wstring(n) + L".CAB");
            if (FileExists(p)) {
                outCabFile = p;
                outSpNum   = n;
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Step 7 : re-stamp PE header checksum
// ---------------------------------------------------------------------------

// SEH guards: MSVC under /EHsc won't allow __try/__except in functions that
// contain C++ objects with destructors. Wrap each risky call in its own
// minimal-locals function.

static DWORD SafeMapFileAndCheckSum(LPCWSTR path, DWORD* oldSum, DWORD* newSum) {
    DWORD rc = (DWORD)~0u;
    __try {
        rc = MapFileAndCheckSumW(path, oldSum, newSum);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rc = (DWORD)~0u;
    }
    return rc;
}

static bool SafePatchHeaders(BYTE* base, DWORD mapSize, DWORD newSum) {
    bool ok = false;
    __try {
        const auto dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            // not MZ
        } else {
            LONG off = dos->e_lfanew;
            if (off > 0 &&
                (DWORD)off + sizeof(DWORD) <= mapSize &&
                (DWORD)off + sizeof(IMAGE_NT_HEADERS32) <= mapSize) {
                DWORD sig = *(DWORD*)(base + off);
                if (sig == IMAGE_NT_SIGNATURE) {
                    WORD magic = *(WORD*)(base + off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
                    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                        ((PIMAGE_NT_HEADERS32)(base + off))->OptionalHeader.CheckSum = newSum;
                        ok = true;
                    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                               (DWORD)off + sizeof(IMAGE_NT_HEADERS64) <= mapSize) {
                        ((PIMAGE_NT_HEADERS64)(base + off))->OptionalHeader.CheckSum = newSum;
                        ok = true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

static bool PatchCheckSumField(const std::wstring& path, DWORD newSum) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogWarn(L"  Cannot open for checksum (%lu): %s", GetLastError(), path.c_str());
        return false;
    }

    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER)) {
        LogWarn(L"  File too small to be PE: %s", path.c_str());
        CloseHandle(hFile);
        return false;
    }
    // Only the headers matter; cap the mapping to the first 4 KB.
    DWORD mapSize = (DWORD)((fsz.QuadPart < 4096) ? fsz.QuadPart : 4096);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READWRITE, 0, mapSize, nullptr);
    if (!hMap) {
        LogWarn(L"  CreateFileMapping failed (%lu): %s", GetLastError(), path.c_str());
        CloseHandle(hFile);
        return false;
    }
    LPVOID base = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, mapSize);
    if (!base) {
        LogWarn(L"  MapViewOfFile failed (%lu): %s", GetLastError(), path.c_str());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    bool ok = SafePatchHeaders((BYTE*)base, mapSize, newSum);
    if (ok) FlushViewOfFile(base, 0);
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

static bool FixCheckSumOne(const std::wstring& path) {
    DWORD oldSum = 0, newSum = 0;
    DWORD rc = SafeMapFileAndCheckSum(path.c_str(), &oldSum, &newSum);
    if (rc != CHECKSUM_SUCCESS) {
        LogWarn(L"  Checksum recalc failed (rc=%lu) for %s", rc, path.c_str());
        return false;
    }
    if (oldSum == newSum) {
        LogDebug(L"  Checksum already current: %s", path.c_str());
        return true;
    }
    bool ok = PatchCheckSumField(path, newSum);
    if (ok) LogDebug(L"  Checksum %08lX -> %08lX  %s", oldSum, newSum, path.c_str());
    return ok;
}

// Inner helper: must contain only POD locals so __try/__except is legal
// under MSVC /EHsc. Calls back into FixCheckSumOne (which holds the wstring).
static bool DoFixCheckSumThunk(const std::wstring* p) {
    return FixCheckSumOne(*p);
}

static bool SafeFixCheckSumOne(const std::wstring& path) {
    const std::wstring* pp = &path;
    bool r = false;
    __try {
        r = DoFixCheckSumThunk(pp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = false;
    }
    return r;
}

bool FixCheckSumsInTree(const std::wstring& dir) {
    if (!DirExists(dir)) return true;

    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(dir, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return true;

    int total = 0, ok = 0, skipped = 0;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = PathJoin(dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            FixCheckSumsInTree(full);
        } else if (IsPEFile(full)) {
            total++;
            LogDebug(L"  checksumming %s", fd.cFileName);
            bool r = SafeFixCheckSumOne(full);
            if (r) ok++; else skipped++;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    if (total > 0) {
        LogInfo(L"  %s : %d PE files, %d ok, %d skipped",
                dir.c_str(), total, ok, skipped);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 4 : populate the bin folders from a media root
// ---------------------------------------------------------------------------

static const std::vector<std::wstring> COMP_EXTS = {
    L".dl_", L".ex_", L".cp_", L".sy_", L".oc_"
};
static const std::vector<std::wstring> UNCOMP_EXTS = {
    L".dll", L".exe", L".sys"
};

// Map a compressed filename (e.g. "explorer.ex_") to its real-extension form
// ("explorer.exe").  Returns the input unchanged if the extension isn't one of
// the known compressed forms.
//   .dl_ -> .dll
//   .ex_ -> .exe
//   .cp_ -> .cpl
//   .sy_ -> .sys
//   .oc_ -> .ocx
static std::wstring ExpandedNameFor(const std::wstring& compressedName) {
    size_t dot = compressedName.find_last_of(L'.');
    if (dot == std::wstring::npos) return compressedName;
    std::wstring stem = compressedName.substr(0, dot);
    std::wstring ext  = ToLower(compressedName.substr(dot));   // ".dl_"
    if      (ext == L".dl_") ext = L".dll";
    else if (ext == L".ex_") ext = L".exe";
    else if (ext == L".cp_") ext = L".cpl";
    else if (ext == L".sy_") ext = L".sys";
    else if (ext == L".oc_") ext = L".ocx";
    else return compressedName;
    return stem + ext;
}

// Expand one compressed PE (e.g. foo.ex_) into dstDir as foo.exe.
// Uses `expand.exe src dst-file` directly so we control the output filename
// (expand's "dir" form would keep the .ex_ name).
static bool ExpandCompressedToRealExt(const std::wstring& srcCompressed,
                                      const std::wstring& dstDir) {
    std::wstring base   = GetFileNameFromPath(srcCompressed);
    std::wstring outName = ExpandedNameFor(base);
    if (outName == base) {
        // Not a recognised compressed extension; just copy.
        return CopyFileForce(srcCompressed, PathJoin(dstDir, base));
    }
    std::wstring outPath = PathJoin(dstDir, outName);
    // Clear any stale destination so expand doesn't refuse.
    if (FileExists(outPath)) DeleteFileW(outPath.c_str());

    std::wstring cmd = L"expand.exe \"" + srcCompressed + L"\" \"" + outPath + L"\"";
    int rc = RunCommand(cmd);
    if (rc != 0) {
        LogError(L"expand failed (rc=%d) for %s", rc, srcCompressed.c_str());
        return false;
    }
    return true;
}

static bool PopulateFromMedia(const std::wstring& mediaRoot,
                              Arch arch,
                              const std::wstring& compBins,
                              const std::wstring& uncompBins,
                              const std::wstring& driverBins,
                              const std::wstring& spBins,
                              const std::wstring& wowBins) {
    std::wstring i386  = PathJoin(mediaRoot, L"I386");
    std::wstring archD = PathJoin(mediaRoot, ArchDirName(arch));

    LogInfo(L"Populating bins from %s (arch=%s)",
            mediaRoot.c_str(), ArchDirName(arch));

    // The arch-relative source dir for both comp + uncomp:
    //   x86   -> <media>\I386
    //   AMD64 -> <media>\AMD64
    //   IA64  -> <media>\IA64
    // On 64-bit media, the root \I386 holds the WOW (32-bit-on-64-bit)
    // compressed files; on 32-bit media, there is no WOW directory.
    std::wstring nativeDir = (arch == Arch::X86) ? i386 : archD;

    // (a) compressed PE files in <nativeDir> -> comp_bins (expanded to real ext)
    if (DirExists(nativeDir)) {
        int n = 0;
        for (const auto& f : ListFilesByExt(nativeDir, COMP_EXTS)) {
            if (ExpandCompressedToRealExt(f, compBins)) n++;
        }
        LogInfo(L"  comp_bins:   %d file(s) from %s", n, nativeDir.c_str());
    }

    // (b) uncompressed PE files in <nativeDir> -> uncomp_bins
    if (DirExists(nativeDir)) {
        int n = 0;
        for (const auto& f : ListFilesByExt(nativeDir, UNCOMP_EXTS)) {
            if (CopyFileForce(f, PathJoin(uncompBins, GetFileNameFromPath(f)))) n++;
        }
        LogInfo(L"  uncomp_bins: %d file(s) from %s", n, nativeDir.c_str());
    }

    // (c) Driver.cab -> driver_bins
    {
        std::wstring drvCab;
        for (const wchar_t* sub : { L"I386", L"AMD64", L"IA64" }) {
            std::wstring p = PathJoin(mediaRoot, sub, L"DRIVER.CAB");
            if (FileExists(p)) { drvCab = p; break; }
            p = PathJoin(mediaRoot, sub, L"Driver.cab");
            if (FileExists(p)) { drvCab = p; break; }
        }
        if (!drvCab.empty()) ExtractCab(drvCab, driverBins);
        else                 LogWarn(L"  Driver.cab not found on %s", mediaRoot.c_str());
    }

    // (d) SP*.CAB -> servicepack_bins
    {
        std::wstring spCab; int spNum = 0;
        if (HasServicePackCab(mediaRoot, spCab, spNum)) ExtractCab(spCab, spBins);
        else                                            LogInfo(L"  No SP*.CAB on %s", mediaRoot.c_str());
    }

    // (e) 64-bit only: WOW = compressed PE files in the *root* \I386 dir.
    // (On 32-bit media there is no WOW; \I386 is the native dir handled above.)
    if (arch == Arch::AMD64 || arch == Arch::IA64) {
        if (DirExists(i386)) {
            int n = 0;
            for (const auto& f : ListFilesByExt(i386, COMP_EXTS)) {
                if (ExpandCompressedToRealExt(f, wowBins)) n++;
            }
            LogInfo(L"  wow_bins:    %d file(s) from %s", n, i386.c_str());
        } else {
            LogWarn(L"  WOW source \\I386 not found at %s", mediaRoot.c_str());
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 3 : staging tree
// ---------------------------------------------------------------------------

static void FillPaths(Paths& p) {
    p.iso1Bins            = PathJoin(p.root, L"ISO_1");
    p.iso1CompBins        = PathJoin(p.iso1Bins, L"comp_bins");
    p.iso1UncompBins      = PathJoin(p.iso1Bins, L"uncomp_bins");
    p.iso1DriverBins      = PathJoin(p.iso1Bins, L"driver_bins");
    p.iso1ServicepackBins = PathJoin(p.iso1Bins, L"servicepack_bins");
    p.iso1WowBins         = PathJoin(p.iso1Bins, L"wow_bins");

    p.iso2Bins            = PathJoin(p.root, L"ISO_2");
    p.iso2CompBins        = PathJoin(p.iso2Bins, L"comp_bins");
    p.iso2UncompBins      = PathJoin(p.iso2Bins, L"uncomp_bins");
    p.iso2DriverBins      = PathJoin(p.iso2Bins, L"driver_bins");
    p.iso2ServicepackBins = PathJoin(p.iso2Bins, L"servicepack_bins");
    p.iso2WowBins         = PathJoin(p.iso2Bins, L"wow_bins");

    p.resources           = PathJoin(p.root, L"Resources");

    p.procRoot            = PathJoin(p.root, L"ISO_1_processed");
    p.procComp            = PathJoin(p.procRoot, L"comp_bins");
    p.procUncomp          = PathJoin(p.procRoot, L"uncomp_bins");
    p.procDriver          = PathJoin(p.procRoot, L"driver_bins");
    p.procServicepack     = PathJoin(p.procRoot, L"servicepack_bins");
    p.procWow             = PathJoin(p.procRoot, L"wow_bins");
}

static bool BuildStagingTree(const Paths& p) {
    LogInfo(L"Building staging tree under %s", p.root.c_str());
    const std::wstring* dirs[] = {
        &p.iso1CompBins, &p.iso1UncompBins, &p.iso1DriverBins,
        &p.iso1ServicepackBins, &p.iso1WowBins,
        &p.iso2CompBins, &p.iso2UncompBins, &p.iso2DriverBins,
        &p.iso2ServicepackBins, &p.iso2WowBins,
        &p.resources,
        &p.procComp, &p.procUncomp, &p.procDriver,
        &p.procServicepack, &p.procWow
    };
    for (auto* d : dirs) if (!MakeDirs(*d)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Step 4-prep: many of the files in comp_bins are still .dl_/.ex_ etc.
// To extract their resources we have to expand each one to a temp PE first.
// We do this only for the ISO_2 side (the "donor").  We pipe the expanded
// files into a temp folder, run resource extraction, then drop them.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pipeline driver
// ---------------------------------------------------------------------------

static std::wstring AskDir(const wchar_t* prompt, bool mustExist) {
    while (true) {
        std::wstring s = Prompt(prompt);
        if (s.empty()) {
            wprintf(L"  empty, please try again.\n");
            continue;
        }
        if (mustExist && !DirExists(s)) {
            wprintf(L"  not a directory: %s\n", s.c_str());
            continue;
        }
        return s;
    }
}

// ---------------------------------------------------------------------------
// Hex Editing Structures & Enumerations
// ---------------------------------------------------------------------------

enum class TargetOs {
    Win2000,
    WinXP,
    Win2003,
    Win2003x64
};

struct HexEditDef {
    const wchar_t* from;
    const wchar_t* to;
};

// ---------------------------------------------------------------------------
// Strict Base-ISO Only Detection Logic
// ---------------------------------------------------------------------------

static TargetOs DetectBaseOs(const std::wstring& iso1Root) {
    // 1. Rule 4: AMD64 folder exists? -> Windows Server 2003 x64
    if (DirExists(PathJoin(iso1Root, L"AMD64"))) {
        return TargetOs::Win2003x64;
    }

    // Determine the main subfolder on the Base ISO (usually I386)
    std::wstring distributionDir = PathJoin(iso1Root, L"I386");
    if (!DirExists(distributionDir)) {
        distributionDir = iso1Root; // Fallback if paths are flattened
    }

    auto fileExistsCaseInsensitive = [&](const wchar_t* name) {
        std::wstring standardPath = PathJoin(distributionDir, name);
        if (FileExists(standardPath)) return true;
        
        // Quick fallback check for lower-case variants
        std::wstring lowerName = name;
        for (auto& c : lowerName) c = towlower(c);
        return FileExists(PathJoin(distributionDir, lowerName));
    };

    // 2. Rule 3: HIVESXS.INF exists but AMD64 doesn't? -> Windows Server 2003
    if (fileExistsCaseInsensitive(L"HIVESXS.INF")) {
        return TargetOs::Win2003;
    }

    // 3. Rule 2: WINNTBBU.DL_ (or .DLL) exists but HIVESXS.INF doesn't? -> Windows XP
    if (fileExistsCaseInsensitive(L"WINNTBBU.DL_") || fileExistsCaseInsensitive(L"WINNTBBU.DLL")) {
        return TargetOs::WinXP;
    }

    // 4. Rule 1: WINNTBBU.DL_ (or .DLL) absent -> Windows 2000
    return TargetOs::Win2000;
}

// ---------------------------------------------------------------------------
// Patching Helper
// ---------------------------------------------------------------------------

static void ApplyPatchesToFile(const std::wstring& path, const std::vector<HexEditDef>& edits) {
    if (!FileExists(path)) {
        return;
    }

    for (const auto& edit : edits) {
        int hits = HexPatchFile(path, HexBytes(edit.from), HexBytes(edit.to));
        if (hits > 0) {
            LogInfo(L"    [+] Patched %d instance(s) in %s: %s -> %s", 
                    hits, GetFileNameFromPath(path).c_str(), edit.from, edit.to);
        }
    }
}

// ---------------------------------------------------------------------------
// Main Hex Editing Orchestrator
// ---------------------------------------------------------------------------

void ApplyHexEditsToUncompressed(const Paths& p, int spNum) {
    // Strictly uses p.iso1 (the base installation media layout root)
    TargetOs os = DetectBaseOs(p.iso1);

    // Targets to alter reside inside p.procComp
    std::wstring setupapi = PathJoin(p.procComp, L"setupapi.dll");
    if (!FileExists(setupapi)) setupapi = PathJoin(p.procComp, L"SETUPAPI.DLL");

    std::wstring syssetup = PathJoin(p.procComp, L"syssetup.dll");
    if (!FileExists(syssetup)) syssetup = PathJoin(p.procComp, L"SYSSETUP.DLL");

    std::wstring sfc_os = PathJoin(p.procComp, L"sfc_os.dll");
    if (!FileExists(sfc_os)) sfc_os = PathJoin(p.procComp, L"SFC_OS.DLL");

    LogInfo(L"\n=== Step: Applying Hex Edits ===");

    switch (os) {
        case TargetOs::Win2000:
            LogInfo(L"Detected Base OS: Windows 2000");
            ApplyPatchesToFile(syssetup, {
                {L"00558BEC81EC040200", L"0033C0C20400909090"},
                {L"743856565656",       L"743833C0EB29"},
                {L"395D0856570F8455",   L"85DB9056570F8455"},
                {L"8B44240883E800",     L"31C0C208009090"}
            });
            break;

        case TargetOs::WinXP:
            LogInfo(L"Detected Base OS: Windows XP (SP%d)", spNum);
            if (spNum < 2) {
                ApplyPatchesToFile(setupapi, { {L"558BEC8B452C", L"33C0C230002C"} });
                ApplyPatchesToFile(syssetup, {
                    {L"8B44240833D2",   L"31C0C2080090"},
                    {L"395D080F842B01", L"85DB900F842B01"}
                });
            } else {
                ApplyPatchesToFile(setupapi, { {L"8BFF558BEC8B452C", L"33C0C230008B452C"} });
                ApplyPatchesToFile(syssetup, {
                    {L"DB395D088945FC0F",   L"DB85DB908945FC0F"},
                    {L"8BFF558BEC8B450C33", L"31C0C208008B450C33"}
                });
            }
            break;

        case TargetOs::Win2003:
            LogInfo(L"Detected Base OS: Windows Server 2003 (SP%d)", spNum);
            if (spNum == 0) {
                ApplyPatchesToFile(setupapi, { {L"8BFF558BEC8B452C", L"33C0C230008B452C"} });
                ApplyPatchesToFile(syssetup, {
                    {L"DB395D088945FC0F", L"DB85DB908945FC0F"},
                    {L"8B44240833D2",     L"31C0C2080090"}
                });
            } else {
                ApplyPatchesToFile(setupapi, { {L"558BEC8B452C", L"33C0C230002C"} });
                ApplyPatchesToFile(syssetup, {
                    {L"DB395D088945FC0F",     L"DB85DB908945FC0F"},
                    {L"8BFF558BEC8B450C33D2", L"31C0C208008B450C33D2"}
                });
            }
            break;

        case TargetOs::Win2003x64:
            LogInfo(L"Detected Base OS: Windows Server 2003 x64");
            ApplyPatchesToFile(setupapi, { 
                {L"32A2DF2D992B0000000000000000000000", L"32A2DF2D992B0000000000000000000040"} 
            });
            ApplyPatchesToFile(sfc_os, { 
                {L"530061006600650062006F006F0074", L"45006D006200650064006400650064"} 
            });
            break;
    }
}

// ---------------------------------------------------------------------------
// Post-Step 10: Help & HTML documentation mirroring
// ---------------------------------------------------------------------------

static void CopyHelpHtmlRecursive(const std::wstring& currentSrcDir, 
                                  const std::wstring& iso2Root, 
                                  const std::wstring& outRoot, 
                                  int& count) 
{
    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(currentSrcDir, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    auto endsWith = [](const std::wstring& str, const std::wstring& suffix) {
        if (str.length() < suffix.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    };

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring srcPath = PathJoin(currentSrcDir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Traverse subdirectories recursively
            CopyHelpHtmlRecursive(srcPath, iso2Root, outRoot, count);
        } else {
            std::wstring nameLower = ToLower(fd.cFileName);
            
            // Match compressed and uncompressed documentation variants
            if (endsWith(nameLower, L".ht_") || endsWith(nameLower, L".htm") ||
                endsWith(nameLower, L".ch_") || endsWith(nameLower, L".chm") ||
                endsWith(nameLower, L".hl_") || endsWith(nameLower, L".hlp")) 
            {
                // Calculate relative path suffix from the resource root folder
                std::wstring relPath = srcPath.substr(iso2Root.length());
                std::wstring dstPath = outRoot + relPath;

                // Ensure target subdirectories exist (e.g. out\I386, out\I386\LANG)
                size_t lastSlash = dstPath.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos) {
                    MakeDirs(dstPath.substr(0, lastSlash));
                }

                // Overwrite/add into the output media folder
                if (CopyFileForce(srcPath, dstPath)) {
                    count++;
                    LogDebug(L"  [+] Mirrored documentation file: %s", relPath.c_str());
                }
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

void ApplyHelpHtmlOverwrites(const std::wstring& outRoot, const std::wstring& iso2Root) {
    LogInfo(L"\n=== Post-Step 10: Copy Help & HTML files from Resource ISO ===");
    int count = 0;
    CopyHelpHtmlRecursive(iso2Root, iso2Root, outRoot, count);
    LogInfo(L"  [+] Added/overwrote %d Help/HTML documentation file(s).", count);
}

bool RunPipeline() {
    Paths p;

    // ---------------- Step 1 ----------------
    wprintf(L"\n");
    wprintf(L"+-----------------------------------------------------------------+\n");
    wprintf(L"|         wininst_patcher - install media resource cross-stamp    |\n");
    wprintf(L"+-----------------------------------------------------------------+\n");
    wprintf(L"\n");
    wprintf(L"This tool patches a Windows 2000 / XP / 2003 install medium with\n");
    wprintf(L"PE resources taken from a second medium. You will need:\n");
    wprintf(L"\n");
    wprintf(L"  Base ISO      The medium you want to keep. Its PE binaries are\n");
    wprintf(L"                rewritten in place; its directory layout, boot\n");
    wprintf(L"                files, and non-PE content are preserved.\n");
    wprintf(L"\n");
    wprintf(L"  Resource ISO  The donor medium. Its binaries are scanned for\n");
    wprintf(L"                resources (typically string tables, dialogs,\n");
    wprintf(L"                accelerators, menus) which are then attached to\n");
    wprintf(L"                or substituted into the Base ISO's binaries.\n");
    wprintf(L"\n");
    wprintf(L"Both inputs must be local writable directories (mounted ISOs are\n");
    wprintf(L"read-only and will not work). The output folder receives the final\n");
    wprintf(L"patched media tree.\n");
    wprintf(L"\n");
    wprintf(L"=== Step 1: Inputs ===\n");
    p.iso1 = AskDir(L"Path to BASE ISO     (target media root)   : ", true);
    p.iso2 = AskDir(L"Path to RESOURCE ISO (donor  media root)   : ", true);

    Arch arch1, arch2;
    if (!DetectArch(p.iso1, arch1)) return false;
    if (!DetectArch(p.iso2, arch2)) return false;
    if (arch1 != arch2) {
        LogWarn(L"Architecture mismatch: Base=%s, Resource=%s -- continuing with Base arch.",
                ArchDirName(arch1), ArchDirName(arch2));
    }
    LogInfo(L"Detected architecture: %s", ArchDirName(arch1));

    std::wstring spDummy; int spNum = 0;
    bool sp1 = HasServicePackCab(p.iso1, spDummy, spNum);
    bool sp2 = HasServicePackCab(p.iso2, spDummy, spNum);
    bool doSp = sp1 || sp2;
    LogInfo(L"Service pack processing: %s", doSp ? L"ENABLED" : L"skipped (no SP*.CAB found)");

    bool doWow = (arch1 == Arch::AMD64 || arch1 == Arch::IA64);

    // ---------------- Step 2 ----------------
    wprintf(L"\n=== Step 2: Output folder ===\n");
    p.output = AskDir(L"Path to output folder (must be empty): ", false);
    MakeDirs(p.output);
    {
        // Empty check
        WIN32_FIND_DATAW fd; std::wstring pat = PathJoin(p.output, L"*");
        HANDLE h = FindFirstFileW(pat.c_str(), &fd);
        bool empty = true;
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
                    empty = false; break;
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        if (!empty) {
            std::wstring ans = Prompt(L"Output folder is not empty. Continue anyway? [y/N]: ");
            if (ans != L"y" && ans != L"Y") {
                LogError(L"Aborted by user.");
                return false;
            }
        }
    }
    p.root = PathJoin(GetExeDir(), L"_work");
    FillPaths(p);

    // ---------------- Pre-Step 3: language detection + mode ----------------
    wprintf(L"\n=== Detect ISO languages (hivedef.inf / INTL_LOCALE) ===\n");
    DWORD lang1 = 0, lang2 = 0;
    bool gotLang1 = DetectMediaLangId(p.iso1, lang1);
    bool gotLang2 = DetectMediaLangId(p.iso2, lang2);

    wprintf(L"\n");
    if (gotLang1) wprintf(L"  Base ISO     : 0x%04X (%lu) - %s\n", lang1, lang1, LangIdName(lang1));
    else          wprintf(L"  Base ISO     : <unable to detect>\n");
    if (gotLang2) wprintf(L"  Resource ISO : 0x%04X (%lu) - %s\n", lang2, lang2, LangIdName(lang2));
    else          wprintf(L"  Resource ISO : <unable to detect>\n");
    wprintf(L"\n");

    // Mode prompt: Attach (A) or Replace (R)
    wprintf(L"Choose how Resource-ISO resources should be applied to the Base:\n");
    wprintf(L"  A  Attach   - keep extracted lang IDs as-is. The Base binary will\n");
    wprintf(L"                end up with both its existing language and the new\n");
    wprintf(L"                one side-by-side, where the OS picks the right one\n");
    wprintf(L"                via fallback.\n");
    wprintf(L"  R  Replace  - rename every extracted .bin from lang%lu to lang%lu\n",
            gotLang2 ? lang2 : 0UL, gotLang1 ? lang1 : 0UL);
    wprintf(L"                before importing, so the Base's existing entries\n");
    wprintf(L"                are overwritten with the donor's content.\n");
    wprintf(L"\n");

    bool doRename = false;
    while (true) {
        std::wstring ans = Prompt(L"Mode [A/R]: ");
        if (ans.empty()) continue;
        wchar_t c = (wchar_t)::towupper(ans[0]);
        if (c == L'A') { doRename = false; break; }
        if (c == L'R') { doRename = true;  break; }
        wprintf(L"  please enter A or R.\n");
    }

    if (doRename && (!gotLang1 || !gotLang2)) {
        LogWarn(L"Replace mode selected but a language ID could not be detected;");
        LogWarn(L"resources will not be renamed (effectively running Attach).");
        doRename = false;
    }
    if (doRename && lang1 == lang2) {
        LogInfo(L"Both ISOs have the same language; nothing to rename.");
        doRename = false;
    }
    LogInfo(L"Mode: %s", doRename ? L"REPLACE (rename .bin lang suffix)"
                                  : L"ATTACH (keep .bin lang suffix as-is)");

    // ---------------- Step 3 ----------------
    wprintf(L"\n=== Step 3: Build staging tree ===\n");
    LogInfo(L"Staging root: %s", p.root.c_str());
    RemoveTree(p.root);
    if (!BuildStagingTree(p)) return false;

    // ---------------- Step 4 ----------------
    wprintf(L"\n=== Step 4: Populate bins ===\n");
    PopulateFromMedia(p.iso1, arch1,
                      p.iso1CompBins, p.iso1UncompBins,
                      p.iso1DriverBins,
                      doSp ? p.iso1ServicepackBins : L"",
                      doWow ? p.iso1WowBins : L"");
    PopulateFromMedia(p.iso2, arch2,
                      p.iso2CompBins, p.iso2UncompBins,
                      p.iso2DriverBins,
                      doSp ? p.iso2ServicepackBins : L"",
                      doWow ? p.iso2WowBins : L"");

    // Clear R/H/S attributes on uncomp_bins (files copied from CD/DVD inherit
    // read-only). BeginUpdateResource refuses read-only files.
    LogInfo(L"  clearing read-only on uncomp_bins...");
    ClearReadOnlyInDir(p.iso1UncompBins);
    ClearReadOnlyInDir(p.iso2UncompBins);
    // Same for the comp/wow bins - they were just expanded out so they should
    // already be read/write, but be defensive.
    ClearReadOnlyInDir(p.iso1CompBins);
    ClearReadOnlyInDir(p.iso2CompBins);
    if (doWow) {
        ClearReadOnlyInDir(p.iso1WowBins);
        ClearReadOnlyInDir(p.iso2WowBins);
    }

    // ---------------- Cross-arch w-prefix strip ----------------
    // When the Base is 64-bit (AMD64/IA64) and the donor is 32-bit (i386),
    // the Base's WOW binaries are prefixed with 'w' (e.g. "waccess.cpl") to
    // distinguish them from native 64-bit ones. The donor has the unprefixed
    // names (e.g. "access.cpl"), so the extracted .bin filenames key off the
    // unprefixed name. To make resource matching work, we rename the Base's
    // w-prefixed files to their unprefixed form here, and rename them back
    // after step 7 so step 8 can compress them under their original names.
    // ---------------- Cross-arch w-prefix strip ----------------
    // When the Base is 64-bit (AMD64/IA64) and the donor is 32-bit (i386),
    // the Base's WOW binaries (the ones in <root>\I386 of the 64-bit medium)
    // are prefixed with 'w' (e.g. "waccess.cpl") to distinguish them from
    // their native 64-bit counterparts. The donor has the unprefixed names
    // (e.g. "access.cpl"), so the extracted .bin filenames key off the
    // unprefixed name. To make resource matching work, we rename only the
    // Base's wow_bins entries to their unprefixed form here, and rename them
    // back after step 7 so step 8 emits the original names.
    std::vector<WRename> wLog;
    bool wStrip = (arch1 != Arch::X86) && (arch2 == Arch::X86);
    if (wStrip) {
        wprintf(L"\n=== Cross-arch: stripping 'w' prefix on Base wow_bins ===\n");
        int n = StripWPrefixInDir(p.iso1WowBins, wLog);
        LogInfo(L"  renamed %d files in wow_bins.", n);
    }

    // ---------------- Step 5 ----------------
    wprintf(L"\n=== Step 5: Extract resources from Resource ISO ===\n");
    // comp_bins / wow_bins were already expanded to real PE extensions in
    // Step 4, so they can be fed directly to the extractor.
    ExtractResourcesFromFolder(p.iso2CompBins,        p.resources);
    ExtractResourcesFromFolder(p.iso2UncompBins,      p.resources);
    ExtractResourcesFromFolder(p.iso2DriverBins,      p.resources);
    if (doSp)  ExtractResourcesFromFolder(p.iso2ServicepackBins, p.resources);
    if (doWow) ExtractResourcesFromFolder(p.iso2WowBins, p.resources);

    // Replace mode: rename _lang<src>.bin -> _lang<dst>.bin so they overwrite
    // the Base ISO's existing language slot rather than adding a new one.
    if (doRename) {
        int n = RenameBinLangSuffix(p.resources, lang2, lang1);
        LogInfo(L"  renamed %d .bin files (lang %lu -> %lu).", n, lang2, lang1);
    }

    // ---------------- Step 6 ----------------
    wprintf(L"\n=== Step 6: Replace resources on Base ISO binaries ===\n");
    ReplaceResources(p.iso1CompBins,        p.resources, p.procComp,        false);
    ReplaceResources(p.iso1UncompBins,      p.resources, p.procUncomp,      false);
    ReplaceResources(p.iso1DriverBins,      p.resources, p.procDriver,      false);
    if (doSp)  ReplaceResources(p.iso1ServicepackBins, p.resources, p.procServicepack, false);
    if (doWow) ReplaceResources(p.iso1WowBins,         p.resources, p.procWow,         false);

    // Make sure patched output is writable for the checksum patch step.
    ClearReadOnlyInDir(p.procComp);
    ClearReadOnlyInDir(p.procUncomp);
    ClearReadOnlyInDir(p.procDriver);
    if (doSp)  ClearReadOnlyInDir(p.procServicepack);
    if (doWow) ClearReadOnlyInDir(p.procWow);
	// Call the updated orchestrator using p.procComp paths
    ApplyHexEditsToUncompressed(p, spNum);
    // ---------------- Step 7 ----------------
    wprintf(L"\n=== Step 7: Recalculate PE checksums ===\n");
    FixCheckSumsInTree(p.procRoot);
    // ---- Restore w-prefixes on the patched output (so step 8 emits original names)
    if (wStrip) {
        wprintf(L"\n=== Cross-arch: restoring 'w' prefix on patched output ===\n");
        // Step 6 wrote into procWow under the *unprefixed* names; remap each
        // entry's dir from iso1WowBins -> procWow and apply the inverse rename.
        std::vector<WRename> restoreLog;
        for (const auto& r : wLog) {
            if (r.dir != p.iso1WowBins) continue;
            // r.toName is the unprefixed file (e.g. "access.cpl"); rename it
            // back to r.fromName ("waccess.cpl").
            restoreLog.push_back({p.procWow, r.toName, r.fromName});
        }
        RestoreWPrefixes(restoreLog);
        // Also restore the source bins themselves so cleanup logs look right.
        RestoreWPrefixes(wLog);
    }

    // ---------------- Step 8 ----------------
    wprintf(L"\n=== Step 8: Build output ===\n");
    std::wstring outArchDir = PathJoin(p.output, ArchDirName(arch1));
    MakeDirs(outArchDir);
    // For IA64/AMD64 the WOW (32-bit) files go into <output>\I386
    std::wstring outI386Dir = PathJoin(p.output, L"I386");
    if (doWow) MakeDirs(outI386Dir);

    // 8a) compress proc_comp -> outArchDir
    LogInfo(L"  (a) compressing comp_bins -> %s", outArchDir.c_str());
    CompressFolderPerFile(p.procComp, outArchDir);

    // 8b) copy proc_uncomp -> outArchDir
    LogInfo(L"  (b) copying uncomp_bins -> %s", outArchDir.c_str());
    CopyTreeForce(p.procUncomp, outArchDir);

    // 8c) driver merge + Driver.cab
    LogInfo(L"  (c) merging driver_bins and rebuilding Driver.cab");
    CopyTreeNoOverwrite(p.iso1DriverBins, p.procDriver);
    {
        std::wstring drvOut = PathJoin(outArchDir, L"Driver.cab");
        BuildCab(p.procDriver, drvOut);
    }

    // 8d) servicepack merge + SP*.CAB
    if (doSp) {
        LogInfo(L"  (d) merging servicepack_bins and rebuilding SP*.CAB");
        CopyTreeNoOverwrite(p.iso1ServicepackBins, p.procServicepack);
        // figure out the SP number to use as the filename
        std::wstring spCab; int n = 0;
        if (HasServicePackCab(p.iso1, spCab, n) || HasServicePackCab(p.iso2, spCab, n)) {
            std::wstring spOut = PathJoin(outArchDir,
                                          L"SP" + std::to_wstring(n) + L".CAB");
            BuildCab(p.procServicepack, spOut);
        } else {
            LogWarn(L"  Could not determine SP number; skipping CAB build.");
        }
    }

    // 8e) compress proc_wow -> I386 (only on 64-bit)
    if (doWow) {
        LogInfo(L"  (e) compressing wow_bins -> %s", outI386Dir.c_str());
        CompressFolderPerFile(p.procWow, outI386Dir);
    }

    // ---------------- Step 9 ----------------
    wprintf(L"\n=== Step 9: Copy remainder of ISO_1 ===\n");
    CopyTreeNoOverwrite(p.iso1, p.output);

    // ---------------- Step 10 ----------------
    wprintf(L"\n=== Step 10: Cleanup ===\n");
    RemoveTree(p.root);

    // ---------------- Post-step-10 output fixups ----------------
    wprintf(L"\n=== Post-step-10: Output folder fixups ===\n");
    PostStep10Fixups(p.output, p.iso1, p.iso2, arch1, arch2,
                     gotLang1 ? lang1 : 0,
                     gotLang2 ? lang2 : 0,
                     doRename);
	ApplyHelpHtmlOverwrites(p.output, p.iso2);
    LogInfo(L"Done. Output is at %s", p.output.c_str());
    return true;
}

// ===========================================================================
// Cross-arch w-prefix rename
// ===========================================================================

static int StripWPrefixInDir(const std::wstring& dir, std::vector<WRename>& log) {
    if (!DirExists(dir)) return 0;
    int n = 0;

    WIN32_FIND_DATAW fd = {};
    std::wstring pat = PathJoin(dir, L"w*");
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring name = fd.cFileName;
        if (name.empty() || (name[0] != L'w' && name[0] != L'W')) continue;
        // Only rename real PE-extension files - skip e.g. winnt.txt, winhelp.txt.
        std::wstring lower = ToLower(name);
        bool isPE =
            EndsWithI(lower, L".dll") || EndsWithI(lower, L".exe") ||
            EndsWithI(lower, L".sys") || EndsWithI(lower, L".cpl") ||
            EndsWithI(lower, L".ocx") || EndsWithI(lower, L".mui");
        if (!isPE) continue;

        std::wstring stripped = name.substr(1); // drop leading 'w' / 'W'
        if (stripped.empty()) continue;

        std::wstring oldPath = PathJoin(dir, name);
        std::wstring newPath = PathJoin(dir, stripped);

        // If the unprefixed name already exists in the same dir, skip - the
        // collision means we can't unambiguously rename back.
        if (FileExists(newPath)) {
            LogWarn(L"  skip rename (target exists): %s", name.c_str());
            continue;
        }
        if (!MoveFileW(oldPath.c_str(), newPath.c_str())) {
            LogWarn(L"  rename failed (%lu): %s", GetLastError(), name.c_str());
            continue;
        }
        log.push_back({dir, name, stripped});
        n++;
        LogDebug(L"  %s -> %s", name.c_str(), stripped.c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

static void RestoreWPrefixes(const std::vector<WRename>& log) {
    int restored = 0, missing = 0;
    for (const auto& r : log) {
        std::wstring src = PathJoin(r.dir, r.fromName);  // e.g. proc\access.cpl
        std::wstring dst = PathJoin(r.dir, r.toName);    // e.g. proc\waccess.cpl
        if (!FileExists(src)) {
            // Step 6's no-resource-match drop may have removed it.
            missing++;
            continue;
        }
        if (FileExists(dst)) DeleteFileW(dst.c_str());
        if (MoveFileW(src.c_str(), dst.c_str())) {
            restored++;
        } else {
            LogWarn(L"  restore rename failed (%lu): %s -> %s",
                    GetLastError(), r.fromName.c_str(), r.toName.c_str());
        }
    }
    LogInfo(L"  restored %d (missing/skipped: %d) in %s",
            restored, missing,
            log.empty() ? L"(no entries)" : log.front().dir.c_str());
}

// ===========================================================================
// Post-step-10 output fixups (sub-tasks I-X)
// ===========================================================================

namespace {

// Read entire file as text, decoding as UTF-8 (no BOM handling - files
// written by this tool are always plain UTF-8 without a BOM; if a source
// INF happens to use the system ANSI codepage instead, the UTF-8 decode
// will simply fail and we fall back to ANSI for that read only).
bool LoadInfText(const std::wstring& path, std::wstring& text) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    if (sz.QuadPart > 0x4000000) { CloseHandle(h); return false; }
    std::string raw((size_t)sz.QuadPart, '\0');
    DWORD rd = 0;
    BOOL ok = ReadFile(h, raw.data(), (DWORD)raw.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok) return false;

    if (!raw.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), (int)raw.size(), nullptr, 0);
        if (n > 0) {
            text.resize(n);
            MultiByteToWideChar(CP_UTF8, 0, raw.data(), (int)raw.size(), &text[0], n);
            return true;
        }
    }
    // Not valid UTF-8 - fall back to ANSI for this read.
    int n = MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), nullptr, 0);
    text.resize(n);
    if (n > 0) MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), &text[0], n);
    return true;
}

// Write `text` as plain UTF-8, no BOM.
bool SaveInfText(const std::wstring& path, const std::wstring& text) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LogWarn(L"  cannot write %s (%lu)", path.c_str(), GetLastError());
        return false;
    }
    DWORD wrote = 0;
    int need = WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(),
                                   nullptr, 0, nullptr, nullptr);
    std::string narrow(need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(),
                        &narrow[0], need, nullptr, nullptr);
    WriteFile(h, narrow.data(), (DWORD)narrow.size(), &wrote, nullptr);
    CloseHandle(h);
    return true;
}

// Locate a file under the per-arch dir or root of the output (or ISO_1).
// Tries: <root>\<archDir>\<name>, then <root>\I386\<name>, then <root>\<name>.
// `archDir` is e.g. "AMD64" / "IA64" / "I386".
std::wstring FindOutputFile(const std::wstring& root, const wchar_t* archDir,
                            const wchar_t* name) {
    std::wstring p = PathJoin(root, archDir, name);
    if (FileExists(p)) return p;
    p = PathJoin(root, L"I386", name);
    if (FileExists(p)) return p;
    p = PathJoin(root, name);
    if (FileExists(p)) return p;
    return L"";
}

// Replace the value of an INF-style line of the form
//     <key> <sep> "<oldHex>"
// where <sep> is '=' (intl.inf's [DefaultValues]) or also '=' (hivedef/hivesys
// INSTALL_LANGUAGE or INTL_LOCALE). We don't try to be a real INF parser - we
// match by key + quoted hex, case-insensitively, within the relevant section.
//
// `sectionFilter` if non-empty restricts edits to the given [section].
// Returns the number of lines edited.
int RewriteQuotedHexValue(std::wstring& text,
                          const std::wstring& key,
                          const std::wstring& newQuoted,
                          const std::wstring& sectionFilter)
{
    // Walk lines, tracking the current section header.
    int edits = 0;
    size_t pos = 0;
    std::wstring curSection;
    std::wstring out;
    out.reserve(text.size() + 32);

    while (pos < text.size()) {
        size_t nl = text.find_first_of(L"\r\n", pos);
        std::wstring line = text.substr(pos, (nl == std::wstring::npos ? text.size() : nl) - pos);
        size_t advanced = (nl == std::wstring::npos ? text.size() : nl);

        // Section header?
        std::wstring trimmed = line;
        size_t a = 0;
        while (a < trimmed.size() && (trimmed[a] == L' ' || trimmed[a] == L'\t')) a++;
        if (a < trimmed.size() && trimmed[a] == L'[') {
            size_t close = trimmed.find(L']', a);
            if (close != std::wstring::npos) {
                curSection = trimmed.substr(a + 1, close - a - 1);
            }
        }

        bool sectionOk = sectionFilter.empty() ||
                         _wcsicmp(curSection.c_str(), sectionFilter.c_str()) == 0;

        bool edited = false;
        if (sectionOk) {
            // Look for: <whitespace>*<key><whitespace>*=<whitespace>*"<hex>"
            std::wstring upperLine = ToUpper(line);
            std::wstring upperKey  = ToUpper(key);
            size_t kpos = upperLine.find(upperKey);
            if (kpos != std::wstring::npos) {
                size_t after = kpos + upperKey.size();
                // skip whitespace
                while (after < line.size() && (line[after] == L' ' || line[after] == L'\t')) after++;
                if (after < line.size() && line[after] == L'=') {
                    after++;
                    while (after < line.size() && (line[after] == L' ' || line[after] == L'\t')) after++;
                    if (after < line.size() && line[after] == L'"') {
                        size_t qend = line.find(L'"', after + 1);
                        if (qend != std::wstring::npos) {
                            // Replace the "...." token with newQuoted
                            std::wstring replaced = line.substr(0, after) + newQuoted +
                                                    line.substr(qend + 1);
                            out.append(replaced);
                            edits++;
                            edited = true;
                        }
                    }
                }
            }
        }
        if (!edited) out.append(line);

        // Append the line terminator(s)
        if (nl == std::wstring::npos) break;
        if (text[nl] == L'\r' && nl + 1 < text.size() && text[nl + 1] == L'\n') {
            out.append(L"\r\n");
            pos = nl + 2;
        } else {
            out.append(1, text[nl]);
            pos = nl + 1;
        }
        (void)advanced;
    }
    text = std::move(out);
    return edits;
}

// Convenience: load, edit, save. Returns number of edits.
int EditInfFile(const std::wstring& path,
                const std::wstring& key,
                const std::wstring& newQuoted,
                const std::wstring& sectionFilter)
{
    std::wstring text;
    if (!LoadInfText(path, text)) {
        LogWarn(L"  cannot read %s", path.c_str());
        return 0;
    }
    int n = RewriteQuotedHexValue(text, key, newQuoted, sectionFilter);
    if (n == 0) {
        if (sectionFilter.empty()) {
            LogInfo(L"  %s: no '%s' line found",
                    GetFileNameFromPath(path).c_str(), key.c_str());
        } else {
            LogInfo(L"  %s: no '%s' line found in [%s]",
                    GetFileNameFromPath(path).c_str(), key.c_str(),
                    sectionFilter.c_str());
        }
        return 0;
    }
    if (!SaveInfText(path, text)) return 0;
    LogInfo(L"  %s: %d edit(s) for '%s' -> %s",
            GetFileNameFromPath(path).c_str(), n, key.c_str(), newQuoted.c_str());
    return n;
}

// ---------------------------------------------------------------------------
// East-Asian (CJK) language-pack section merging (Post-step-10, VII-X)
// ---------------------------------------------------------------------------

// Maps a LANGID (as produced by DetectMediaLangId / hivedef.inf INTL_LOCALE)
// to the decimal LCID string used in the "txtsetup_<NNNN>.txt" /
// "hivesys_<NNNN>.txt" / "hivesft_<NNNN>.txt" filenames shipped alongside the
// patcher for that language. Returns L"" for any language we don't have a
// special fixup for.
//
// Originally this covered only the CJK (Chinese Simp./Trad., Korean,
// Japanese) "complex script" languages, but Arabic and Hebrew need the same
// kind of [nls]/[AddReg] fixup-file treatment (they're complex-script /
// bidirectional languages with their own NLS, font, and keyboard-layout
// data), so they're included here too. The name CjkLangTag is kept for
// source-compat with existing callers even though the set now also includes
// non-CJK complex-script languages.
std::wstring CjkLangTag(DWORD langId) {
    switch (langId) {
        case 0x0804: return L"2052"; // Chinese (Simplified)
        case 0x0404: return L"1028"; // Chinese (Traditional)
        case 0x0412: return L"1042"; // Korean
        case 0x0411: return L"1041"; // Japanese
        default:     return L"";
    }
}

// Read a text file that may be UTF-8 or ANSI. The language-section files
// (txtsetup_2052.txt etc.) are hand-authored and may contain CJK/Arabic/
// Hebrew characters in either encoding; no BOM is expected or required.
bool LoadAnyText(const std::wstring& path, std::wstring& text) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    if (sz.QuadPart > 0x4000000) { CloseHandle(h); return false; }
    std::string raw((size_t)sz.QuadPart, '\0');
    DWORD rd = 0;
    BOOL ok = ReadFile(h, raw.data(), (DWORD)raw.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok) return false;

    // UTF-8 (no BOM expected)
    if (!raw.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), (int)raw.size(), nullptr, 0);
        if (n > 0) {
            text.resize(n);
            MultiByteToWideChar(CP_UTF8, 0, raw.data(), (int)raw.size(), &text[0], n);
            return true;
        }
    }
    // Fall back to ANSI
    int n = MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), nullptr, 0);
    text.resize(n);
    if (n > 0) MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), &text[0], n);
    return true;
}

std::wstring TrimWS(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == L' ' || s[a] == L'\t' || s[a] == L'\r')) a++;
    while (b > a && (s[b-1] == L' ' || s[b-1] == L'\t' || s[b-1] == L'\r')) b--;
    return s.substr(a, b - a);
}

// If `line` (after trimming) is a "[Section]" / ["quoted section"] header,
// returns true and fills `name` with the raw bracket interior.
bool IsSectionHeader(const std::wstring& line, std::wstring& name) {
    std::wstring t = TrimWS(line);
    if (t.size() < 2 || t.front() != L'[') return false;
    size_t close = t.find(L']');
    if (close == std::wstring::npos) return false;
    name = t.substr(1, close - 1);
    return true;
}

// One [Section] block from a language-fixup text file: the header line
// (including its line terminator) and everything up to (but not including)
// the next section header, also including terminators.
struct RawSection {
    std::wstring name;
    std::wstring header;
    std::wstring body;
};

// Split `text` into an ordered list of [Section] blocks. Any content before
// the first header (there shouldn't be any in our language files) is dropped.
std::vector<RawSection> ParseSections(const std::wstring& text) {
    std::vector<RawSection> out;
    size_t pos = 0;
    RawSection* cur = nullptr;
    while (pos < text.size()) {
        size_t nl = text.find_first_of(L"\r\n", pos);
        size_t lineEnd = (nl == std::wstring::npos) ? text.size() : nl;
        size_t termEnd = lineEnd;
        if (nl != std::wstring::npos) {
            termEnd = (text[nl] == L'\r' && nl + 1 < text.size() && text[nl + 1] == L'\n')
                          ? nl + 2 : nl + 1;
        }
        std::wstring lineNoTerm   = text.substr(pos, lineEnd - pos);
        std::wstring lineWithTerm = text.substr(pos, termEnd - pos);

        std::wstring secName;
        if (IsSectionHeader(lineNoTerm, secName)) {
            out.push_back({secName, lineWithTerm, L""});
            cur = &out.back();
        } else if (cur) {
            cur->body += lineWithTerm;
        }

        if (nl == std::wstring::npos) break;
        pos = termEnd;
    }
    return out;
}

// Location of a [Section] block (matched by name, case-insensitive) inside
// an existing INF-style text.
struct TargetSection {
    size_t headerStart;  // offset of the "[Section]" line
    size_t headerEnd;    // offset just past that line's terminator
    size_t bodyEnd;      // offset of the next section header, or text.size()
};

bool FindSection(const std::wstring& text, const std::wstring& name, TargetSection& out) {
    size_t pos = 0;
    bool found = false;
    while (pos < text.size()) {
        size_t nl = text.find_first_of(L"\r\n", pos);
        size_t lineEnd = (nl == std::wstring::npos) ? text.size() : nl;
        size_t termEnd = lineEnd;
        if (nl != std::wstring::npos) {
            termEnd = (text[nl] == L'\r' && nl + 1 < text.size() && text[nl + 1] == L'\n')
                          ? nl + 2 : nl + 1;
        }
        std::wstring lineNoTerm = text.substr(pos, lineEnd - pos);
        std::wstring secName;
        bool isHeader = IsSectionHeader(lineNoTerm, secName);

        if (!found) {
            if (isHeader && _wcsicmp(TrimWS(secName).c_str(), TrimWS(name).c_str()) == 0) {
                out.headerStart = pos;
                out.headerEnd   = termEnd;
                found = true;
            }
        } else if (isHeader) {
            out.bodyEnd = pos;
            return true;
        }

        if (nl == std::wstring::npos) break;
        pos = termEnd;
    }
    if (found) { out.bodyEnd = text.size(); return true; }
    return false;
}

// Merge every [Section] from `srcSections` into `text`:
//  - If a section's (trimmed, case-insensitive) name matches `replaceSection`
//    (non-empty), the *entire* matching section in `text` (header + body) is
//    replaced wholesale by the source section. If no match exists, the source
//    section is appended at EOF.
//  - For every other section, the source section's body lines are appended to
//    the end of the matching section's body in `text` (just before the next
//    section header, or EOF). If no matching section exists in `text`, the
//    whole source section (header + body) is appended at EOF.
// Returns the number of source sections processed.
int MergeInfSections(std::wstring& text,
                     const std::vector<RawSection>& srcSections,
                     const std::wstring& replaceSection) {
    int n = 0;
    for (const auto& src : srcSections) {
        bool doReplace = !replaceSection.empty() &&
                         _wcsicmp(TrimWS(src.name).c_str(), TrimWS(replaceSection).c_str()) == 0;

        TargetSection ts;
        bool found = FindSection(text, src.name, ts);

        if (doReplace) {
            std::wstring block = src.header + src.body;
            if (found) {
                text = text.substr(0, ts.headerStart) + block + text.substr(ts.bodyEnd);
            } else {
                if (!text.empty() && text.back() != L'\n' && text.back() != L'\r') text += L"\r\n";
                text += block;
            }
        } else {
            if (found) {
                text = text.substr(0, ts.bodyEnd) + src.body + text.substr(ts.bodyEnd);
            } else {
                if (!text.empty() && text.back() != L'\n' && text.back() != L'\r') text += L"\r\n";
                text += src.header + src.body;
            }
        }
        n++;
    }
    return n;
}

// Merge the [Section]s of the language-fixup file at `srcPath` into the INF
// file at `dstPath`. The section named `replaceSection` (if non-empty) is
// replaced wholesale; every other section is appended to its counterpart (or
// added as a new section). Returns the number of sections merged, 0 if
// `srcPath` had no sections, or -1 on I/O error.
int MergeInfFile(const std::wstring& dstPath, const std::wstring& srcPath,
                 const std::wstring& replaceSection) {
    std::wstring srcText;
    if (!LoadAnyText(srcPath, srcText)) {
        LogWarn(L"  cannot read %s", srcPath.c_str());
        return -1;
    }
    auto sections = ParseSections(srcText);
    if (sections.empty()) {
        LogWarn(L"  %s contains no [section] headers - nothing to merge",
                GetFileNameFromPath(srcPath).c_str());
        return 0;
    }

    std::wstring dstText;
    if (!LoadInfText(dstPath, dstText)) {
        LogWarn(L"  cannot read %s", dstPath.c_str());
        return -1;
    }

    int n = MergeInfSections(dstText, sections, replaceSection);

    if (!SaveInfText(dstPath, dstText)) return -1;
    LogInfo(L"  %s: merged %d section(s) from %s",
            GetFileNameFromPath(dstPath).c_str(), n, GetFileNameFromPath(srcPath).c_str());
    return n;
}

// Like MergeInfFile, but the source is raw [section] text already in memory
// (rather than a file on disk). Used for the built-in, hardcoded [nls] blocks
// in Step XII, where there is no per-language fixup file to read.
int MergeInfTextFromString(const std::wstring& dstPath, const std::wstring& srcText,
                           const std::wstring& replaceSection) {
    auto sections = ParseSections(srcText);
    if (sections.empty()) return 0;

    std::wstring dstText;
    if (!LoadInfText(dstPath, dstText)) {
        LogWarn(L"  cannot read %s", dstPath.c_str());
        return -1;
    }

    int n = MergeInfSections(dstText, sections, replaceSection);

    if (!SaveInfText(dstPath, dstText)) return -1;
    LogInfo(L"  %s: merged %d section(s)", GetFileNameFromPath(dstPath).c_str(), n);
    return n;
}

// ---------------------------------------------------------------------------
// Step XII: per-language [nls] section text for txtsetup.sif.
// ---------------------------------------------------------------------------

// Returns the [nls] section body (everything after the "[nls]" header line)
// for the given language ID, or an empty string if there is no entry for it
// (in which case [nls] is left untouched).
//
// Arabic and Hebrew are NOT listed here: they're now handled like the CJK
// languages, via their own txtsetup_<NNNN>.txt / hivesys_<NNNN>.txt /
// hivesft_<NNNN>.txt fixup files in Step VII (see CjkLangTag), since they
// need full complex-script ([nls], font, keyboard layout) treatment, not
// just the [nls] block. Step XII recognizes this via CjkLangTag and defers
// to Step VII instead of warning about a missing entry.
std::wstring NlsSectionForLang(DWORD langId) {
    switch (langId) {
        // US English
        case 0x0409:
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_437.nls,437,c_850.nls,850\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0409\r\n"
                L"OemHalFont       = vgaoem.fon\r\n"
                L"DefaultLayout    = 00000409\r\n";

        // Brazilian Portuguese, and every language that's "same as Brazilian
        // Portuguese except UnicodeCasetable".
        case 0x0416:  // Portuguese (Brazil)
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0416\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000416\r\n";

        case 0x0c0a:  // Spanish
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0c0a\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 0000040a\r\n";

        case 0x040c:  // French
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,040c\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 0000040c\r\n";

        case 0x0407:  // German
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0407\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000407\r\n";

        case 0x0410:  // Italian
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0410\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000410\r\n";

        case 0x0413:  // Dutch
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0413\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000413\r\n";

        case 0x0816:  // Portuguese (Portugal)
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0816\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000816\r\n";

        case 0x041d:  // Swedish
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,041d\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 0000041d\r\n";

        case 0x0406:  // Danish
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0406\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000406\r\n";

        case 0x040b:  // Finnish
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,040b\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 0000040b\r\n";

        case 0x0414:  // Norwegian
            return
                L"AnsiCodepage     = c_1252.nls,1252\r\n"
                L"OemCodepage      = c_850.nls,850,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,0414\r\n"
                L"OemHalFont       = vga850.fon\r\n"
                L"DefaultLayout    = 00000414\r\n";

        // Czech, and every language that's "same as Czech except UnicodeCasetable".
        case 0x0405:  // Czech
            return
                L"AnsiCodepage     = c_1250.nls,1250\r\n"
                L"OemCodepage      = c_852.nls,852,c_437.nls,437\r\n"
                L"MacCodepage      = c_10029.nls,10029\r\n"
                L"UnicodeCasetable = l_intl.nls,0405\r\n"
                L"OemHalFont       = vga852.fon\r\n"
                L"DefaultLayout    = 00000405\r\n";

        case 0x040e:  // Hungarian
            return
                L"AnsiCodepage     = c_1250.nls,1250\r\n"
                L"OemCodepage      = c_852.nls,852,c_437.nls,437\r\n"
                L"MacCodepage      = c_10029.nls,10029\r\n"
                L"UnicodeCasetable = l_intl.nls,040e\r\n"
                L"OemHalFont       = vga852.fon\r\n"
                L"DefaultLayout    = 0000040e\r\n";

        case 0x0415:  // Polish
            return
                L"AnsiCodepage     = c_1250.nls,1250\r\n"
                L"OemCodepage      = c_852.nls,852,c_437.nls,437\r\n"
                L"MacCodepage      = c_10029.nls,10029\r\n"
                L"UnicodeCasetable = l_intl.nls,0415\r\n"
                L"OemHalFont       = vga852.fon\r\n"
                L"DefaultLayout    = 00000415\r\n";

        case 0x0419:  // Russian
            return
                L"AnsiCodepage     = c_1251.nls,1251\r\n"
                L"OemCodepage      = c_866.nls,866,c_437.nls,437\r\n"
                L"MacCodepage      = c_10007.nls,10007\r\n"
                L"UnicodeCasetable = l_intl.nls,0419\r\n"
                L"OemHalFont       = vga866.fon\r\n"
                L"DefaultLayout    = 00000419\r\n";

        case 0x041f:  // Turkish
            return
                L"AnsiCodepage     = c_1254.nls,1254\r\n"
                L"OemCodepage      = c_857.nls,857,c_437.nls,437\r\n"
                L"MacCodepage      = c_10000.nls,10000\r\n"
                L"UnicodeCasetable = l_intl.nls,041f\r\n"
                L"OemHalFont       = vga857.fon\r\n"
                L"DefaultLayout    = 0000041f\r\n";

        case 0x0408:  // Greek
            return
                L"AnsiCodepage     = c_1253.nls,1253\r\n"
                L"OemCodepage      = c_737.nls,737,c_437.nls,437\r\n"
                L"MacCodepage      = c_10006.nls,10006\r\n"
                L"UnicodeCasetable = l_intl.nls,0408\r\n"
                L"OemHalFont       = vga737.fon\r\n"
                L"DefaultLayout    = 00000408\r\n";

        default:
            return L"";  // unknown / CJK languages handled separately
    }
}

} // anonymous namespace

static bool PostStep10Fixups(const std::wstring& outRoot,
                             const std::wstring& iso1Root,
                             const std::wstring& iso2Root,
                             Arch arch, Arch donorArch,
                             DWORD baseLang, DWORD newLang, bool replaceMode)
{
    (void)baseLang;  // only used implicitly via Replace mode logic
    const wchar_t* archDir = ArchDirName(arch);
    std::wstring archAbs = PathJoin(outRoot, archDir);

    // (I) ntdll.dll -> system32\ntdll.dll
    {
        std::wstring src = PathJoin(archAbs, L"NTDLL.DLL");
        if (!FileExists(src)) src = PathJoin(archAbs, L"ntdll.dll");
        std::wstring dstDir = PathJoin(archAbs, L"SYSTEM32");
        std::wstring dst = PathJoin(dstDir, L"NTDLL.DLL");
        if (FileExists(src)) {
            MakeDirs(dstDir);
            if (CopyFileForce(src, dst))
                LogInfo(L"  (I)   %s -> %s", src.c_str(), dst.c_str());
        } else {
            LogWarn(L"  (I)   NTDLL.DLL not found under %s", archAbs.c_str());
        }
    }

    // (II) usetup.exe -> system32\smss.exe
    {
        std::wstring src = PathJoin(archAbs, L"USETUP.EXE");
        if (!FileExists(src)) src = PathJoin(archAbs, L"usetup.exe");
        std::wstring dstDir = PathJoin(archAbs, L"SYSTEM32");
        std::wstring dst = PathJoin(dstDir, L"SMSS.EXE");
        if (FileExists(src)) {
            MakeDirs(dstDir);
            if (CopyFileForce(src, dst))
                LogInfo(L"  (II)  %s -> %s", src.c_str(), dst.c_str());
        } else {
            LogWarn(L"  (II)  USETUP.EXE not found under %s", archAbs.c_str());
        }
    }

    // Decide what hex value to write. If Replace mode + we have a donor lang,
    // that's the new locale; otherwise no edit is meaningful.
    bool doInfEdits = replaceMode && newLang != 0;
    wchar_t newHex8[16] = {0};
    wchar_t newHex4[16] = {0};
    if (doInfEdits) {
        swprintf_s(newHex8, L"\"%08x\"", newLang);   // intl.inf  / hivedef.inf style
        swprintf_s(newHex4, L"\"%04x\"", newLang);   // hivesys.inf style (4 hex digits, zero-padded)
    }

    // (III) intl.inf  [DefaultValues]   Locale = "00000409" -> new
    if (doInfEdits) {
        std::wstring intlInf = FindOutputFile(outRoot, archDir, L"intl.inf");
        if (intlInf.empty()) intlInf = FindOutputFile(outRoot, archDir, L"INTL.INF");
        if (intlInf.empty()) LogWarn(L"  (III) intl.inf not found");
        else                 EditInfFile(intlInf, L"Locale", newHex8, L"DefaultValues");
    } else {
        LogInfo(L"  (III) skipped (Attach mode or no donor lang).");
    }

    // (IV) hivesys.inf  INSTALL_LANGUAGE="0409" -> new (no leading zeros)
    if (doInfEdits) {
        std::wstring hsInf = FindOutputFile(outRoot, archDir, L"hivesys.inf");
        if (hsInf.empty()) hsInf = FindOutputFile(outRoot, archDir, L"HIVESYS.INF");
        if (hsInf.empty()) LogWarn(L"  (IV)  hivesys.inf not found");
        else               EditInfFile(hsInf, L"INSTALL_LANGUAGE", newHex4, L"");
    }

    // (V) hivedef.inf  INTL_LOCALE="00000409" -> new
    if (doInfEdits) {
        std::wstring hdInf = FindOutputFile(outRoot, archDir, L"hivedef.inf");
        if (hdInf.empty()) hdInf = FindOutputFile(outRoot, archDir, L"HIVEDEF.INF");
        if (hdInf.empty()) LogWarn(L"  (V)   hivedef.inf not found");
        else               EditInfFile(hdInf, L"INTL_LOCALE", newHex8, L"");
    }

    // (VI) Replace PIDGEN.DLL with the original from ISO_1 (unaffected by patch).
    {
        // Find PIDGEN.DLL on ISO_1 (look in per-arch dir, then I386, then root).
        std::wstring src;
        for (const wchar_t* sub : { archDir, L"I386", L"" }) {
            std::wstring cand = (*sub) ? PathJoin(iso1Root, sub, L"PIDGEN.DLL")
                                       : PathJoin(iso1Root, L"PIDGEN.DLL");
            if (FileExists(cand)) { src = cand; break; }
            cand = (*sub) ? PathJoin(iso1Root, sub, L"pidgen.dll")
                          : PathJoin(iso1Root, L"pidgen.dll");
            if (FileExists(cand)) { src = cand; break; }
        }
        if (src.empty()) {
            LogWarn(L"  (VI)  PIDGEN.DLL not found on Base ISO");
        } else {
            // Place at the same relative location it lived on ISO_1.
            std::wstring rel = src.substr(iso1Root.size());
            // strip leading separator if present
            while (!rel.empty() && (rel[0] == L'\\' || rel[0] == L'/')) rel.erase(0, 1);
            std::wstring dst = PathJoin(outRoot, rel);
            if (CopyFileForce(src, dst))
                LogInfo(L"  (VI)  PIDGEN.DLL restored from Base -> %s", dst.c_str());
        }
    }

    // (VI-b) Always keep the original, unpatched KERNEL32.DLL (or its
    // compressed KERNEL32.DL_ form) from ISO_1 in the output. KERNEL32 must
    // never carry resource-replacement changes, since it is loaded very
    // early in setup and a patched copy can break text-mode setup itself.
    {
        const wchar_t* names[] = { L"KERNEL32.DLL", L"kernel32.dll",
                                   L"KERNEL32.DL_", L"kernel32.dl_" };
        bool restored = false;
        for (const wchar_t* sub : { archDir, L"I386", L"" }) {
            for (const wchar_t* n : names) {
                std::wstring cand = (*sub) ? PathJoin(iso1Root, sub, n)
                                           : PathJoin(iso1Root, n);
                if (!FileExists(cand)) continue;

                std::wstring rel = cand.substr(iso1Root.size());
                while (!rel.empty() && (rel[0] == L'\\' || rel[0] == L'/')) rel.erase(0, 1);
                std::wstring dst = PathJoin(outRoot, rel);
                if (CopyFileForce(cand, dst)) {
                    LogInfo(L"  (VI-b) KERNEL32 restored unpatched from Base -> %s", dst.c_str());
                    restored = true;
                }
            }
        }
        if (!restored) {
            LogWarn(L"  (VI-b) KERNEL32.DLL/.DL_ not found on Base ISO - "
                    L"output may contain a resource-patched copy.");
        }
    }

    // (VI-b) Always keep the original, unpatched rsaenh.DLL (or its
    // compressed rsaenh.DL_ form) from ISO_1 in the output. rsaenh must
    // never carry resource-replacement changes, since it is loaded very
    // early in setup and a patched copy can break text-mode setup itself.
    {
        const wchar_t* names[] = { L"rsaenh.DLL", L"rsaenh.dll",
                                   L"rsaenh.DL_", L"rsaenh.dl_" };
        bool restored = false;
        for (const wchar_t* sub : { archDir, L"I386", L"" }) {
            for (const wchar_t* n : names) {
                std::wstring cand = (*sub) ? PathJoin(iso1Root, sub, n)
                                           : PathJoin(iso1Root, n);
                if (!FileExists(cand)) continue;

                std::wstring rel = cand.substr(iso1Root.size());
                while (!rel.empty() && (rel[0] == L'\\' || rel[0] == L'/')) rel.erase(0, 1);
                std::wstring dst = PathJoin(outRoot, rel);
                if (CopyFileForce(cand, dst)) {
                    LogInfo(L"  (VI-b) rsaenh restored unpatched from Base -> %s", dst.c_str());
                    restored = true;
                }
            }
        }
        if (!restored) {
            LogWarn(L"  (VI-b) rsaenh.DLL/.DL_ not found on Base ISO - "
                    L"output may contain a resource-patched copy.");
        }
    }

    // (VI-b) Always keep the original, unpatched dssenh.DLL (or its
    // compressed dssenh.DL_ form) from ISO_1 in the output. dssenh must
    // never carry resource-replacement changes, since it is loaded very
    // early in setup and a patched copy can break text-mode setup itself.
    {
        const wchar_t* names[] = { L"dssenh.DLL", L"dssenh.dll",
                                   L"dssenh.DL_", L"dssenh.dl_" };
        bool restored = false;
        for (const wchar_t* sub : { archDir, L"I386", L"" }) {
            for (const wchar_t* n : names) {
                std::wstring cand = (*sub) ? PathJoin(iso1Root, sub, n)
                                           : PathJoin(iso1Root, n);
                if (!FileExists(cand)) continue;

                std::wstring rel = cand.substr(iso1Root.size());
                while (!rel.empty() && (rel[0] == L'\\' || rel[0] == L'/')) rel.erase(0, 1);
                std::wstring dst = PathJoin(outRoot, rel);
                if (CopyFileForce(cand, dst)) {
                    LogInfo(L"  (VI-b) dssenh restored unpatched from Base -> %s", dst.c_str());
                    restored = true;
                }
            }
        }
        if (!restored) {
            LogWarn(L"  (VI-b) dssenh.DLL/.DL_ not found on Base ISO - "
                    L"output may contain a resource-patched copy.");
        }
    }

    // ---------------------------------------------------------------------
    // (VII)-(X) Complex-script language fixups: Chinese Simp./Trad., Korean,
    // Japanese.
    //
    // These only apply in Replace mode, and only when the target language is
    // one of the complex-script languages we have fixup files for. The fixup
    // files (txtsetup_<NNNN>.txt, hivesys_<NNNN>.txt, hivesft_<NNNN>.txt,
    // where <NNNN> is the decimal LCID, e.g. 2052 for zh-CN) must sit next to
    // this executable. If a fixup file is missing, a warning is logged and
    // the corresponding file must be edited by hand.
    // ---------------------------------------------------------------------
    if (doInfEdits) {
        std::wstring tag = CjkLangTag(newLang);
        if (tag.empty()) {
            LogInfo(L"  (VII-X) skipped (target language %s has no complex-script fixup files).",
                    LangIdName(newLang));
        } else {
            LogInfo(L"  Complex-script fixups for %s (LCID %s)", LangIdName(newLang), tag.c_str());
            std::wstring exeDir = GetExeDir();

            // (VII) txtsetup.sif <- txtsetup_<tag>.txt
            //   [nls] section is REPLACED wholesale; every other section is
            //   APPENDED to its counterpart (or added if missing).
            {
                std::wstring srcFile = PathJoin(exeDir, L"txtsetup_" + tag + L".txt");
                if (!FileExists(srcFile)) {
                    LogWarn(L"  (VII) %s not found next to the executable - "
                            L"txtsetup.sif must be edited manually for this language.",
                            GetFileNameFromPath(srcFile).c_str());
                } else {
                    std::wstring dstFile = FindOutputFile(outRoot, archDir, L"txtsetup.sif");
                    if (dstFile.empty()) dstFile = FindOutputFile(outRoot, archDir, L"TXTSETUP.SIF");
                    if (dstFile.empty()) {
                        LogWarn(L"  (VII) txtsetup.sif not found under %s", outRoot.c_str());
                    } else {
                        MergeInfFile(dstFile, srcFile, L"nls");
                    }
                }
            }

            // (VIII) hivesys.inf <- hivesys_<tag>.txt
            //   Every section is APPENDED to its counterpart (or added if missing).
            {
                std::wstring srcFile = PathJoin(exeDir, L"hivesys_" + tag + L".txt");
                if (!FileExists(srcFile)) {
                    LogWarn(L"  (VIII) %s not found next to the executable - "
                            L"hivesys.inf must be edited manually for this language.",
                            GetFileNameFromPath(srcFile).c_str());
                } else {
                    std::wstring dstFile = FindOutputFile(outRoot, archDir, L"hivesys.inf");
                    if (dstFile.empty()) dstFile = FindOutputFile(outRoot, archDir, L"HIVESYS.INF");
                    if (dstFile.empty()) {
                        LogWarn(L"  (VIII) hivesys.inf not found under %s", outRoot.c_str());
                    } else {
                        MergeInfFile(dstFile, srcFile, L"");
                    }
                }
            }

            // (IX) hivesft.inf <- hivesft_<tag>.txt
            //   Every section is APPENDED to its counterpart (or added if missing).
            {
                std::wstring srcFile = PathJoin(exeDir, L"hivesft_" + tag + L".txt");
                if (!FileExists(srcFile)) {
                    LogWarn(L"  (IX)  %s not found next to the executable - "
                            L"hivesft.inf must be edited manually for this language.",
                            GetFileNameFromPath(srcFile).c_str());
                } else {
                    std::wstring dstFile = FindOutputFile(outRoot, archDir, L"hivesft.inf");
                    if (dstFile.empty()) dstFile = FindOutputFile(outRoot, archDir, L"HIVESFT.INF");
                    if (dstFile.empty()) {
                        LogWarn(L"  (IX)  hivesft.inf not found under %s", outRoot.c_str());
                    } else {
                        MergeInfFile(dstFile, srcFile, L"");
                    }
                }
            }

            // (X) Copy every file from <Resource ISO (donor)>\<donor-arch> to
            //     <output>\<arch>, without overwriting anything already
            //     produced by the pipeline.
            //
            // The destination subfolder is always the *Base*'s arch dir
            // (archDir, e.g. I386 for x86 output, AMD64 for x64 output) -
            // that's the layout of the output media. The source subfolder is
            // the donor's own arch dir, since that's where the donor's files
            // actually live on its media:
            //
            //   Base x86 + Donor x86 -> Output\I386   (from donor I386)
            //   Base x64 + Donor x64 -> Output\AMD64  (from donor AMD64)
            //   Base x64 + Donor x86 -> Output\AMD64  (from donor I386)
            {
                const wchar_t* donorArchDir = ArchDirName(donorArch);
                std::wstring srcDir = PathJoin(iso2Root, donorArchDir);
                std::wstring dstDir = archAbs;
                if (!DirExists(srcDir)) {
                    LogWarn(L"  (X)   %s not found on Resource (donor) ISO", srcDir.c_str());
                } else {
                    LogInfo(L"  (X)   copying %s -> %s (no overwrite)", srcDir.c_str(), dstDir.c_str());
                    CopyTreeNoOverwrite(srcDir, dstDir);
                }
            }
			LogWarn(L"  Replacing the file spddlang.sys (or .sy_) is required for text-mode setup.", outRoot.c_str());
			LogWarn(L"  Make sure to keep the architectures same, build number as close as possible.", outRoot.c_str());
        }

        // (XI) txtsetup.sif: replace the driver-media descriptor fragment
        //   " 1,,,,,,3_,2,1,,,1,2"  ->  "1,,,,,,,2,0,0"
        // This is a literal substring replace across the whole file (the
        // string appears on floppy/disk geometry lines and needs the same
        // fix regardless of language).
        {
            std::wstring sifPath = FindOutputFile(outRoot, archDir, L"txtsetup.sif");
            if (sifPath.empty()) sifPath = FindOutputFile(outRoot, archDir, L"TXTSETUP.SIF");
            if (sifPath.empty()) {
                LogWarn(L"  (XI)  txtsetup.sif not found under %s", outRoot.c_str());
            } else {
                std::wstring text;
                if (!LoadInfText(sifPath, text)) {
                    LogWarn(L"  (XI)  could not read %s", sifPath.c_str());
                } else {
                    const std::wstring kOld = L" 1,,,,,,3_,2,1,,,1,2";
                    const std::wstring kNew = L"1,,,,,,,2,0,0";
                    int replaced = 0;
                    size_t pos = 0;
                    while ((pos = text.find(kOld, pos)) != std::wstring::npos) {
                        text.replace(pos, kOld.size(), kNew);
                        pos += kNew.size();
                        replaced++;
                    }
                    if (replaced == 0) {
                        LogWarn(L"  (XI)  pattern not found in %s - may already be patched or layout differs",
                                GetFileNameFromPath(sifPath).c_str());
                    } else {
                        if (!SaveInfText(sifPath, text)) {
                            LogWarn(L"  (XI)  could not write %s", sifPath.c_str());
                        } else {
                            LogInfo(L"  (XI)  %s: replaced %d occurrence(s) of media descriptor",
                                    GetFileNameFromPath(sifPath).c_str(), replaced);
                        }
                    }
                }
            }
        }

        // (XII) txtsetup.sif: replace the [nls] section wholesale with the
        // hardcoded values for newLang. Complex-script languages (CJK,
        // Arabic, Hebrew) already got their [nls] replaced in Step VII via a
        // fixup file, so only the remaining languages are handled here. If
        // the language has no entry in NlsSectionForLang() and is also not a
        // complex-script language, the section is left untouched and a
        // warning is emitted.
        {
            std::wstring nlsBody = NlsSectionForLang(newLang);
            if (nlsBody.empty()) {
                if (CjkLangTag(newLang).empty()) {
                    // Truly unknown language - no fixup file will have patched it either
                    LogWarn(L"  (XII) no [nls] data for language 0x%04X (%s) - "
                            L"txtsetup.sif [nls] section must be edited manually",
                            newLang, LangIdName(newLang));
                } else {
                    // Complex-script language: already handled by Step VII
                    LogInfo(L"  (XII) [nls] for %s already handled by Step VII.",
                            LangIdName(newLang));
                }
            } else {
                std::wstring sifPath = FindOutputFile(outRoot, archDir, L"txtsetup.sif");
                if (sifPath.empty()) sifPath = FindOutputFile(outRoot, archDir, L"TXTSETUP.SIF");
                if (sifPath.empty()) {
                    LogWarn(L"  (XII) txtsetup.sif not found under %s", outRoot.c_str());
                } else {
                    // Synthesise a minimal [nls] block and use the existing
                    // section-merge infrastructure to replace wholesale.
                    std::wstring srcText = L"[nls]\r\n" + nlsBody;
                    int n = MergeInfTextFromString(sifPath, srcText, L"nls");
                    if (n < 0) {
                        LogWarn(L"  (XII) failed to update [nls] in %s",
                                GetFileNameFromPath(sifPath).c_str());
                    } else {
                        LogInfo(L"  (XII) %s: [nls] replaced for %s",
                                GetFileNameFromPath(sifPath).c_str(),
                                LangIdName(newLang));
                    }
                }
            }
        }
    } else {
        LogInfo(L"  (VII-XII) skipped (Attach mode or no donor lang).");
    }

    return true;
}
