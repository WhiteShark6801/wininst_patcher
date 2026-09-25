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
#include <algorithm>
#include <cwctype>
#include <map>
#include <set>
#include <fstream>
#include <string>
#include <vector>

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
    std::wstring axp64 = PathJoin(mediaRoot, L"AXP64");
    std::wstring alpha = PathJoin(mediaRoot, L"ALPHA");
    std::wstring i386  = PathJoin(mediaRoot, L"I386");

    if (DirExists(ia64))       { outArch = Arch::IA64;  return true; }
    if (DirExists(amd64))      { outArch = Arch::AMD64; return true; }
    if (DirExists(axp64))      { outArch = Arch::AXP64; return true; }
    if (DirExists(alpha))      { outArch = Arch::ALPHA; return true; }
    if (DirExists(i386))       { outArch = Arch::X86;   return true; }

    LogError(L"No I386/AMD64/IA64/AXP64/ALPHA directory under %s", mediaRoot.c_str());
    return false;
}

bool HasServicePackCab(const std::wstring& mediaRoot,
                       std::wstring& outCabFile, int& outSpNum) {
    // Service pack CABs sit in the I386 directory on every NT-family install
    // medium I've seen.  Check both the root and I386.
    const wchar_t* candidates[] = { L"I386", L"AMD64", L"IA64", L"AXP64", L"ALPHA", L"" };
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

bool FixCheckSumsInTree(const std::wstring& dir, ResourceExcludeFn isExcluded) {
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
            FixCheckSumsInTree(full, isExcluded);
        } else if (IsPEFile(full)) {
            // Safe mode: excluded boot-critical files pass through untouched,
            // not even their PE checksum header is re-stamped.
            if (isExcluded && isExcluded(fd.cFileName)) {
                LogDebug(L"  checksum skipped (Safe mode): %s", fd.cFileName);
                continue;
            }
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
    if (!driverBins.empty()) {
        std::wstring drvCab;
        for (const wchar_t* sub : { L"I386", L"AMD64", L"IA64", L"AXP64", L"ALPHA" }) {
            std::wstring p = PathJoin(mediaRoot, sub, L"DRIVER.CAB");
            if (FileExists(p)) { drvCab = p; break; }
            p = PathJoin(mediaRoot, sub, L"Driver.cab");
            if (FileExists(p)) { drvCab = p; break; }
        }
        if (!drvCab.empty()) ExtractCab(drvCab, driverBins);
        else                 LogWarn(L"  Driver.cab not found on %s", mediaRoot.c_str());
    } else {
        LogInfo(L"  driver.cab: skipped");
    }

    // (d) SP*.CAB -> servicepack_bins
    if (!spBins.empty()) {
        std::wstring spCab; int spNum = 0;
        if (HasServicePackCab(mediaRoot, spCab, spNum)) ExtractCab(spCab, spBins);
        else                                            LogInfo(L"  No SP*.CAB on %s", mediaRoot.c_str());
    } else {
        LogInfo(L"  SP*.CAB: skipped");
    }

    // (e) 64-bit only: WOW = compressed PE files in the *root* \I386 dir.
    // (On 32-bit media there is no WOW; \I386 is the native dir handled above.)
    if (IsArch64(arch)) {
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

// Returns true if `path` resides on a mounted CD/DVD drive. Accepts a drive
// root, a path with or without a trailing slash, or a drive-relative path.
static bool IsOpticalMedia(const std::wstring& path) {
    std::wstring root;
    if (path.size() >= 2 && path[1] == L':') {
        root = std::wstring(1, path[0]) + L":\\";
    } else if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') {
        return false; // UNC share - treat as regular folder
    } else {
        return false;
    }
    return GetDriveTypeW(root.c_str()) == DRIVE_CDROM;
}

// ---------------------------------------------------------------------------
// Hex Editing Structures & Enumerations
// ---------------------------------------------------------------------------

enum class TargetOs {
    Win2000,
    WinXP,
    Win2003,
    Win2003x64,
	Win2003IA64    // Itanium: folder IA64 only
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
	if (DirExists(PathJoin(iso1Root, L"IA64"))) {
        return TargetOs::Win2003IA64;
    }
	// DEC Alpha (ALPHA) and Alpha AXP 64-bit (AXP64): no Windows XP / Server
    // 2003 media was ever released for these architectures, so they are always
    // treated strictly as Windows 2000.
	if (DirExists(PathJoin(iso1Root, L"AXP64"))) {
        return TargetOs::Win2000;
    }
	if (DirExists(PathJoin(iso1Root, L"ALPHA"))) {
        return TargetOs::Win2000;
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

// Formats a string to uppercase for robust section matching
static std::wstring ToUpper(std::wstring str) {
    std::transform(str.begin(), str.end(), str.begin(), ::towupper);
    return str;
}

// Trims whitespace from both ends of a line
static std::wstring Trim(const std::wstring& str) {
    size_t first = str.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return L"";
    size_t last = str.find_last_not_of(L" \t\r\n");
    return str.substr(first, (last - first + 1));
}

void AddFontToSourceDisksFiles(const std::wstring& txtsetupPath, const std::wstring& vgaFontName) {
    if (vgaFontName.empty()) {
        LogWarn(L"Skipping txtsetup.sif font injection: Font filename is empty.");
        return;
    }

    std::wifstream inFile(txtsetupPath);
    if (!inFile.is_open()) {
        LogError(L"Failed to open txtsetup.sif for reading: %s", txtsetupPath.c_str());
        return;
    }

    std::vector<std::wstring> lines;
    std::wstring line;
    while (std::getline(inFile, line)) {
        lines.push_back(line);
    }
    inFile.close();

    bool sectionFound = false;
    size_t targetIndex = 0;
    bool alreadyExists = false;
    
    std::wstring newLine = vgaFontName + L"   = 1,,,,,,3_,22,0,0,,1,2";
    std::wstring formattedFontUpper = ToUpper(vgaFontName);

    for (size_t i = 0; i < lines.size(); ++i) {
        std::wstring trimmed = Trim(lines[i]);
        std::wstring upperLine = ToUpper(trimmed);

        // Robust section matching: checks if the string starts with '[SOURCEDISKSFILES]'
        if (upperLine.rfind(L"[SOURCEDISKSFILES]", 0) == 0) {
            sectionFound = true;
            targetIndex = i + 1;
            continue;
        }

        if (sectionFound) {
            // Next section boundaries
            if (!upperLine.empty() && upperLine[0] == L'[') {
                targetIndex = i;
                break;
            }

            // Deduplication matching
            if (upperLine.rfind(formattedFontUpper, 0) == 0) {
                LogInfo(L"Font %s already exists in [SourceDisksFiles]. Updating entry inline.", vgaFontName.c_str());
                lines[i] = newLine;
                alreadyExists = true;
                break;
            }
            
            targetIndex = i + 1;
        }
    }

    if (!sectionFound) {
        LogError(L"[SourceDisksFiles] section header was not detected in txtsetup.sif.");
        return;
    }

    if (!alreadyExists && targetIndex > 0) {
        lines.insert(lines.begin() + targetIndex, newLine);
        LogInfo(L"Successfully injected line: '%s' into txtsetup.sif", newLine.c_str());
    }

    std::wofstream outFile(txtsetupPath, std::ios::trunc);
    if (!outFile.is_open()) {
        LogError(L"Failed to open txtsetup.sif for writing: %s", txtsetupPath.c_str());
        return;
    }

    for (const auto& l : lines) {
        outFile << l << L"\n";
    }
    outFile.close();
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
// IA-64: validate + re-stamp manually-copied pre-patched binaries
// ---------------------------------------------------------------------------
//
// The EPIC instruction set on IA-64 makes automated hex patching of
// setupapi.dll/syssetup.dll infeasible (see ApplyHexEditsToUncompressed).
// Instead the operator supplies already-patched IA-64 builds of these two
// files by hand. Once they've done so we can't skip validation: a wrong-arch
// or wrong-name file dropped in by mistake would silently ship into the
// output media. This function only "translates" the files in the sense of
// verifying they are genuine IA-64 PE images and refreshing their checksum
// field to match the bytes on disk (the checksum a hand-copied file carries
// almost never matches its origin media, since most patchers alter bytes
// without re-stamping).

// Minimal PE machine-type sniff. Mirrors SafePatchHeaders' guarded layout
// walk but only reads the machine field; never touches the checksum here.
static bool SafeReadPeMachine(BYTE* base, DWORD mapSize, WORD* outMachine) {
    bool ok = false;
    __try {
        const auto dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            LONG off = dos->e_lfanew;
            if (off > 0 &&
                (DWORD)off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) <= mapSize) {
                DWORD sig = *(DWORD*)(base + off);
                if (sig == IMAGE_NT_SIGNATURE) {
                    const auto fileHdr =
                        (PIMAGE_FILE_HEADER)(base + off + sizeof(DWORD));
                    *outMachine = fileHdr->Machine;
                    ok = true;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

static bool ReadPeMachineType(const std::wstring& path, WORD& outMachine) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return false;
    }
    DWORD mapSize = (DWORD)((fsz.QuadPart < 4096) ? fsz.QuadPart : 4096);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, mapSize, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, mapSize);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return false; }

    WORD machine = 0;
    bool ok = SafeReadPeMachine((BYTE*)base, mapSize, &machine);
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);

    if (ok) outMachine = machine;
    return ok;
}

// Verifies one manually-copied file is a genuine PE image for the expected
// machine type, then re-stamps its checksum (SafeFixCheckSumOne /
// FixCheckSumOne, same as Step 7 uses for every other binary in the tree) so
// the header matches the on-disk bytes the operator just placed there.
static bool TranslatePrepatchedFile(const std::wstring& path,
                                    const std::wstring& archTag,
                                    WORD expectedMachine,
                                    const wchar_t* machineName) {
    if (!FileExists(path)) {
        LogWarn(L"  [%s] %s not found - was it actually copied in?",
                archTag.c_str(), GetFileNameFromPath(path).c_str());
        return false;
    }

    WORD machine = 0;
    if (!ReadPeMachineType(path, machine)) {
        LogWarn(L"  [%s] %s does not look like a valid PE image.",
                archTag.c_str(), GetFileNameFromPath(path).c_str());
        return false;
    }
    if (machine != expectedMachine) {
        LogWarn(L"  [%s] %s has machine type 0x%04X, expected %s (0x%04X) - "
                L"wrong-architecture file may have been copied by mistake.",
                archTag.c_str(), GetFileNameFromPath(path).c_str(),
                machine, machineName, expectedMachine);
        return false;
    }

    bool ok = SafeFixCheckSumOne(path);
    if (ok) {
        LogInfo(L"  [%s] %s verified (%s PE) and checksum re-stamped.",
                archTag.c_str(), GetFileNameFromPath(path).c_str(), machineName);
    } else {
        LogWarn(L"  [%s] %s is a valid %s PE but its checksum could not be "
                L"re-stamped; setup may reject it.",
                archTag.c_str(), GetFileNameFromPath(path).c_str(), machineName);
    }
    return ok;
}

// Runs the check above over both files the operator was asked to replace.
// Called right after the "press Enter to continue" prompt so any mistake is
// caught immediately instead of surfacing later as a setup failure on real
// hardware for an architecture that cannot be automatically hex-patched
// (IA-64, 32-bit DEC Alpha, and 64-bit Alpha AXP).
//
// The operator drops the pre-patched files into p.iso1CompBins (ISO_1\comp_bins),
// i.e. alongside the rest of the Base ISO's staged binaries, rather than
// directly into p.procComp (ISO_1_processed\comp_bins). This keeps the
// distinction between "Base ISO inputs" and "pipeline outputs" consistent:
// nothing is ever hand-placed straight into the processed/output tree.
//
// Once verified, only these two files get their resources replaced - not the
// whole comp_bins folder (ReplaceResources operates on an entire directory,
// and everything else in comp_bins was already processed back in Step 6).
// To scope it down to just these two files, they're mirrored into a private
// temp staging folder, ReplaceResources is run on that folder alone, and the
// two results are copied over into p.procComp.
static bool TranslateManualPrepatchedBinaries(const Paths& p,
                                              const std::wstring& archTag,
                                              WORD expectedMachine,
                                              const wchar_t* machineName) {
    std::wstring setupapi = PathJoin(p.iso1CompBins, L"setupapi.dll");
    if (!FileExists(setupapi)) setupapi = PathJoin(p.iso1CompBins, L"SETUPAPI.DLL");

    std::wstring syssetup = PathJoin(p.iso1CompBins, L"syssetup.dll");
    if (!FileExists(syssetup)) syssetup = PathJoin(p.iso1CompBins, L"SYSSETUP.DLL");

    LogInfo(L"  [%s] Validating manually-copied pre-patched binaries...", archTag.c_str());
    bool okSetupapi = TranslatePrepatchedFile(setupapi, archTag, expectedMachine, machineName);
    bool okSyssetup = TranslatePrepatchedFile(syssetup, archTag, expectedMachine, machineName);

    if (!okSetupapi || !okSyssetup) {
        LogWarn(L"  [%s] One or more files failed validation. Re-check the "
                L"copied binaries before proceeding.", archTag.c_str());
        return false;
    }

    // Stage just these two files in an isolated temp folder so
    // ReplaceResources (which processes a whole directory) only ever sees
    // them, not the rest of comp_bins.
    std::wstring stageDir = PathJoin(p.procRoot, archTag + L"_stage_comp");
    MakeDirs(stageDir);

    std::wstring stagedSetupapi = PathJoin(stageDir, GetFileNameFromPath(setupapi));
    std::wstring stagedSyssetup = PathJoin(stageDir, GetFileNameFromPath(syssetup));
    bool okStage = CopyFileForce(setupapi, stagedSetupapi) &&
                   CopyFileForce(syssetup, stagedSyssetup);
    if (!okStage) {
        LogWarn(L"  [%s] Could not stage setupapi.dll/syssetup.dll for "
                L"resource replacement.", archTag.c_str());
        return false;
    }

    LogInfo(L"  [%s] Replacing resources for setupapi.dll / syssetup.dll...", archTag.c_str());
    bool okReplace = ReplaceResources(stageDir, p.resources, p.procComp, false, nullptr);
    if (!okReplace) {
        LogWarn(L"  [%s] Resource replacement failed for one or more of the "
                L"%s binaries; check %s.",
                archTag.c_str(), machineName, p.procComp.c_str());
    }
    return okReplace;
}

// ---------------------------------------------------------------------------
// Main Hex Editing Orchestrator
// ---------------------------------------------------------------------------

void ApplyHexEditsToUncompressed(const Paths& p, int spNum) {
    // Strictly uses p.iso1 (the base installation media layout root)
    TargetOs os = DetectBaseOs(p.iso1);

    Arch arch = Arch::X86;
    DetectArch(p.iso1, arch);

    // Targets to alter reside inside p.procComp
    std::wstring setupapi = PathJoin(p.procComp, L"setupapi.dll");
    if (!FileExists(setupapi)) setupapi = PathJoin(p.procComp, L"SETUPAPI.DLL");

    std::wstring syssetup = PathJoin(p.procComp, L"syssetup.dll");
    if (!FileExists(syssetup)) syssetup = PathJoin(p.procComp, L"SYSSETUP.DLL");

    std::wstring sfc_os = PathJoin(p.procComp, L"sfc_os.dll");
    if (!FileExists(sfc_os)) sfc_os = PathJoin(p.procComp, L"SFC_OS.DLL");

    LogInfo(L"\n=== Step: Applying Hex Edits ===");

// Intercept architectures that cannot be automatically hex-patched
// (IA-64 Itanium, 32-bit DEC Alpha, and 64-bit Alpha AXP). The operator must
// supply already-patched setupapi.dll/syssetup.dll by hand, which are then
// validated and resource-replaced like the IA-64 flow.
// ALPHA / AXP64 media is strictly Windows 2000 (no XP / Server 2003 was ever
// released for it), so it receives the Windows 2000 x86-like treatment
// everywhere except here, where the hex patching stays manual.
    if (arch == Arch::IA64 || arch == Arch::ALPHA || arch == Arch::AXP64) {
        const wchar_t* osDesc;
        std::wstring tag;
        WORD machine;
        const wchar_t* machineName;
        const wchar_t* baseOs;
        if (arch == Arch::IA64) {
            osDesc = L"IA-64 Itanium";
            tag    = L"IA-64";
            machine = IMAGE_FILE_MACHINE_IA64;
            machineName = L"IA-64";
            baseOs  = L"Windows Server 2003";
        } else if (arch == Arch::ALPHA) {
            osDesc = L"DEC Alpha (32-bit)";
            tag    = L"ALPHA";
            machine = IMAGE_FILE_MACHINE_ALPHA;
            machineName = L"ALPHA";
            baseOs  = L"Windows 2000";
        } else {
            osDesc = L"Alpha AXP (64-bit)";
            tag    = L"AXP64";
            machine = IMAGE_FILE_MACHINE_ALPHA64;
            machineName = L"AXP64";
            baseOs  = L"Windows 2000";
        }

        LogInfo(L"Detected Base OS: %s", baseOs);
        LogWarn(L"[!] Automated hex patching is impossible for the %s instruction set.", machineName);

        wprintf(L"\n=================================================================\n");
        wprintf(L"MANUAL ACTION REQUIRED FOR %s DEPLOYMENT:\n", osDesc);
        wprintf(L"Please manually place your pre-patched %s binaries into:\n", machineName);
        wprintf(L"--> %s\n\n", p.iso1CompBins.c_str());
        wprintf(L"Ensure both 'setupapi.dll' and 'syssetup.dll' are replaced.\n");
        wprintf(L"They will be verified, then have their resources replaced into:\n");
        wprintf(L"--> %s\n", p.procComp.c_str());
        wprintf(L"=================================================================\n\n");

        wchar_t promptMsg[512];
        swprintf_s(promptMsg,
                   L"Press [Enter] once you have copied the patched %s files to continue...",
                   machineName);
        Prompt(promptMsg);

        if (!TranslateManualPrepatchedBinaries(p, tag, machine, machineName)) {
            LogWarn(L"[!] %s setupapi.dll/syssetup.dll processing did not complete "
                    L"successfully; check the warnings above before shipping this media.",
                    machineName);
        }
        return;
    }

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

// Remap the leading architecture-directory segment of a relative path from the
// donor tree to the output tree.  For example, when a donor I386 medium is
// being used to patch an ALPHA base, "I386\SUPPORT\foo.chm" must land in
// "ALPHA\SUPPORT\foo.chm" - the previous 1:1 mirroring dumped everything into
// the donor's own arch folder.  Both callers pass same-arch directories too,
// in which case the segment is returned unchanged.
static std::wstring RemapArchSegment(const std::wstring& relPath,
                                     Arch donorArch, Arch outArch) {
    // Normalize: drop any leading separator (donor root may or may not end in
    // a backslash, so relPath can start with either "\I386\..." or "I386\...").
    std::wstring norm = relPath;
    while (!norm.empty() && (norm[0] == L'\\' || norm[0] == L'/')) norm.erase(0, 1);

    // First component up to the next separator.
    size_t slash = norm.find_first_of(L"\\/");
    std::wstring head = (slash == std::wstring::npos) ? norm : norm.substr(0, slash);
    std::wstring tail = (slash == std::wstring::npos) ? L""  : norm.substr(slash);

    std::wstring headLower = ToLower(head);
    bool isArchDir =
        headLower == L"i386"  || headLower == L"amd64" ||
        headLower == L"ia64"  || headLower == L"axp64" ||
        headLower == L"alpha";
    if (!isArchDir) return norm;                  // e.g. SUPPORT, LANG - untouched
    if (donorArch == outArch) return norm;        // same-arch: keep structure

    // A 64-bit donor's I386 is its WOW folder; if the output is also 64-bit it
    // has its own I386 WOW folder, so keep it.  Otherwise (incl. a 32-bit
    // ALPHA base) it folds into the output's native arch directory.
    if (headLower == L"i386" && IsArch64(donorArch) && IsArch64(outArch)) return norm;

    return std::wstring(ArchDirName(outArch)) + tail;
}

static void CopyHelpHtmlRecursive(const std::wstring& currentSrcDir, 
                                  const std::wstring& iso2Root, 
                                  const std::wstring& outRoot, 
                                  Arch donorArch, Arch outArch,
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
            CopyHelpHtmlRecursive(srcPath, iso2Root, outRoot, donorArch, outArch, count);
        } else {
            std::wstring nameLower = ToLower(fd.cFileName);
            
            // Match compressed and uncompressed documentation variants
            if (endsWith(nameLower, L".ht_") || endsWith(nameLower, L".htm") ||
                endsWith(nameLower, L".ch_") || endsWith(nameLower, L".chm") ||
                endsWith(nameLower, L".hl_") || endsWith(nameLower, L".hlp")) 
            {
                // Calculate relative path suffix from the resource root folder,
                // then re-target a leading architecture folder (I386->ALPHA, ...).
                std::wstring relPath = srcPath.substr(iso2Root.length());
                relPath = RemapArchSegment(relPath, donorArch, outArch);
                std::wstring dstPath = PathJoin(outRoot, relPath);

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
    Arch donorArch = Arch::X86;
    Arch outArch   = Arch::X86;
    if (!DetectArch(iso2Root, donorArch)) donorArch = Arch::X86;
    if (!DetectArch(outRoot, outArch))    outArch   = Arch::X86;
    LogInfo(L"  donor media arch: %s, output media arch: %s",
            ArchDirName(donorArch), ArchDirName(outArch));

    int count = 0;
    CopyHelpHtmlRecursive(iso2Root, iso2Root, outRoot, donorArch, outArch, count);
    LogInfo(L"  [+] Added/overwrote %d Help/HTML documentation file(s).", count);
}

static bool IsPureInteger(const std::wstring& s) {
    if (s.empty()) return false;
    for (wchar_t c : s) {
        if (!std::iswdigit(c)) return false;
    }
    return true;
}

// Safe mode: files whose base name matches one of the boot-critical kernel /
// HAL families, the driver/service-pack archives, or a loose compressed
// driver are copied through untouched (their resources are never replaced).
// Covers both uncompressed and expanded-compressed name forms.
static bool IsSafeModeExcludedFile(const std::wstring& fileName) {
    std::wstring lower = ToLower(fileName);
    if (StartsWithI(lower, L"ntoskrnl")) return true;   // ntoskrnl.exe
    if (StartsWithI(lower, L"ntkr"))     return true;   // ntkrnlmp.exe and other ntkr*.exe
    if (StartsWithI(lower, L"hal"))      return true;   // hal.dll and hal*.dll variants

    if (lower == L"driver.cab")          return true;   // Driver.cab archive

    // Service-pack archives: SP1.CAB, SP2.CAB, ... (no static list; any
    // "SP"+digits+".CAB" counts).
    if (lower.size() > 6 &&
        StartsWithI(lower, L"sp") &&
        EndsWithI(lower, L".cab")) {
        bool digitsOnly = true;
        for (size_t i = 2; i + 4 < lower.size(); ++i) {
            if (!std::iswdigit(lower[i])) { digitsOnly = false; break; }
        }
        if (digitsOnly) return true;
    }

    // Compressed driver binaries shipped loose on the media.  Drivers stored
    // inside Driver.cab / SP*.CAB are already covered by the cab exclusions
    // above (and their contents are never unpacked to loose names in the
    // safe-mode flow).
    if (EndsWithI(lower, L".sy_"))       return true;
    return false;
}

// Safe mode: after the whole pipeline finishes, re-copy every excluded file
// from the Base ISO onto the output media, mirroring its relative path and
// overwriting whatever the pipeline wrote (e.g. a re-compressed .ex_/.sy_).
// This guarantees the boot-critical kernel/HAL family, Driver.cab / SP*.CAB
// and loose compressed drivers on the output are byte-identical to the Base
// ISO originals.
static void SafeModeRestoreExcludedFiles(const std::wstring& iso1Root,
                                         const std::wstring& outRoot,
                                         int& count) {
    if (!DirExists(iso1Root)) return;

    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(iso1Root, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring srcPath = PathJoin(iso1Root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectories, mirroring the same relative path.
            SafeModeRestoreExcludedFiles(srcPath, PathJoin(outRoot, fd.cFileName), count);
        } else if (IsSafeModeExcludedFile(fd.cFileName)) {
            std::wstring dstPath = PathJoin(outRoot, fd.cFileName);
            // CopyFileForce ensures the target directories exist first.
            if (CopyFileForce(srcPath, dstPath)) {
                count++;
                LogInfo(L"  [+] Safe-mode restore: %s -> %s", fd.cFileName, dstPath.c_str());
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void SafeModeRestoreExcludedFiles(const std::wstring& iso1Root,
                                         const std::wstring& outRoot) {
    int count = 0;
    SafeModeRestoreExcludedFiles(iso1Root, outRoot, count);
    if (count > 0) {
        LogInfo(L"  Safe-mode restore: %d excluded file(s) copied from Base ISO.", count);
    }
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
    wprintf(L"                accelerators, menus) which are then written into\n");
    wprintf(L"                the Base ISO's binaries.\n");
    wprintf(L"\n");
    wprintf(L"Both inputs must be local writable directories (mounted ISOs are\n");
    wprintf(L"read-only and will not work). The output folder receives the final\n");
    wprintf(L"patched media tree.\n");
    wprintf(L"\n");
    wprintf(L"=== Step 1: Inputs ===\n");
    p.iso1 = AskDir(L"Path to BASE ISO     (target media root)   : ", true);
    p.iso2 = AskDir(L"Path to RESOURCE ISO (donor  media root)   : ", true);

    bool baseOptical   = IsOpticalMedia(p.iso1);
    bool donorOptical  = IsOpticalMedia(p.iso2);
    if (baseOptical || donorOptical) {
        wprintf(L"\n  Note: mounted optical (CD/DVD) media detected - Base %s, Resource %s.\n"
                L"  Files copied from those discs carry the read-only attribute;\n"
                L"  it will be cleared in the output before the post-cleanup fixups.\n",
                baseOptical ? L"yes" : L"no", donorOptical ? L"yes" : L"no");
    }

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
    LogInfo(L"Service pack detected on media: %s", doSp ? L"yes" : L"no");

    bool doWow = IsArch64(arch1);

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

    // Mode prompt: Safe (S) or Full (F)
    wprintf(L"Choose how the Base ISO should be processed:\n");
    wprintf(L"  S  Safe  - boot-critical files are left untouched: ntoskrnl.exe,\n");
    wprintf(L"             ntkr*.exe and hal*.dll pass through unchanged, driver.cab\n");
    wprintf(L"             / SP*.CAB are not processed (the originals are kept),\n");
    wprintf(L"             and loose *.sy_ driver files are left as-is.\n");
    wprintf(L"  F  Full  - process everything like usual (every PE binary gets its\n");
    wprintf(L"             resources replaced and Driver.cab / SP*.CAB rebuilt).\n");
    wprintf(L"\n");

    bool safeMode = false;
    while (true) {
        std::wstring ans = Prompt(L"Mode [S/F]: ");
        if (ans.empty()) continue;
        wchar_t c = (wchar_t)::towupper(ans[0]);
        if (c == L'S') { safeMode = true;  break; }
        if (c == L'F') { safeMode = false; break; }
        wprintf(L"  please enter S or F.\n");
    }

    // Attach mode has been retired: resources are always applied in the old
    // Replace fashion.  The extracted .bin language suffix is renamed from the
    // donor language to the Base language so the Base's entries are overwritten
    // with the donor's content (gracefully degraded if a language can't be read
    // from either medium).
    bool doRename = true;
    if (!gotLang1 || !gotLang2) {
        LogWarn(L"A language ID could not be detected for both ISOs; extracted");
        LogWarn(L"resources will not be renamed to the Base language.");
        doRename = false;
    }
    if (doRename && lang1 == lang2) {
        LogInfo(L"Both ISOs have the same language; nothing to rename.");
        doRename = false;
    }
    LogInfo(L"Processing mode: %s", safeMode ? L"SAFE (skip ntoskrnl/ntkr*/hal* + driver.cab + SP*.CAB)"
                                            : L"FULL (process everything)");
    LogInfo(L"Resource application: %s",
            doRename ? L"REPLACE (rename .bin lang suffix to Base)"
                     : L"REPLACE (no rename possible - keeping suffixes as-is)");

    // Safe mode also disables Driver.cab and SP*.CAB end-to-end so those
    // archives and their contents reach the output untouched.
    bool doDriver = !safeMode;
    if (safeMode) {
        LogInfo(L"Safe mode: driver.cab processing disabled - original archive kept.");
        if (doSp) {
            LogInfo(L"Safe mode: SP*.CAB processing disabled - original archive kept.");
            doSp = false;
        }
        LogInfo(L"Safe mode: kernel/HAL binaries (ntoskrnl, ntkr*, hal*) left untouched.");
    }

    // ---------------- Step 3 ----------------
    wprintf(L"\n=== Step 3: Build staging tree ===\n");
    LogInfo(L"Staging root: %s", p.root.c_str());
    RemoveTree(p.root);
    if (!BuildStagingTree(p)) return false;

    // ---------------- Step 4 ----------------
    wprintf(L"\n=== Step 4: Populate bins ===\n");
    PopulateFromMedia(p.iso1, arch1,
                      p.iso1CompBins, p.iso1UncompBins,
                      doDriver ? p.iso1DriverBins : L"",
                      doSp ? p.iso1ServicepackBins : L"",
                      doWow ? p.iso1WowBins : L"");
    PopulateFromMedia(p.iso2, arch2,
                      p.iso2CompBins, p.iso2UncompBins,
                      doDriver ? p.iso2DriverBins : L"",
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
    if (doDriver) ExtractResourcesFromFolder(p.iso2DriverBins, p.resources);
    if (doSp)     ExtractResourcesFromFolder(p.iso2ServicepackBins, p.resources);
    if (doWow)    ExtractResourcesFromFolder(p.iso2WowBins, p.resources);

    // Replace mode: rename _lang<src>.bin -> _lang<dst>.bin so they overwrite
    // the Base ISO's existing language slot rather than adding a new one.
    if (doRename) {
        int n = RenameBinLangSuffix(p.resources, lang2, lang1);
        LogInfo(L"  renamed %d .bin files (lang %lu -> %lu).", n, lang2, lang1);
    }

    // ---------------- Step 6 ----------------
    wprintf(L"\n=== Step 6: Replace resources on Base ISO binaries ===\n");
    ResourceExcludeFn exclude = safeMode ? IsSafeModeExcludedFile : nullptr;
    ReplaceResources(p.iso1CompBins,        p.resources, p.procComp,        false, exclude);
    ReplaceResources(p.iso1UncompBins,      p.resources, p.procUncomp,      false, exclude);
    if (doDriver) ReplaceResources(p.iso1DriverBins,      p.resources, p.procDriver,      false, nullptr);
    if (doSp)     ReplaceResources(p.iso1ServicepackBins, p.resources, p.procServicepack, false, nullptr);
    if (doWow)    ReplaceResources(p.iso1WowBins,         p.resources, p.procWow,         false, exclude);

    // Make sure patched output is writable for the checksum patch step.
    ClearReadOnlyInDir(p.procComp);
    ClearReadOnlyInDir(p.procUncomp);
    if (doDriver) ClearReadOnlyInDir(p.procDriver);
    if (doSp)     ClearReadOnlyInDir(p.procServicepack);
    if (doWow)    ClearReadOnlyInDir(p.procWow);
	// Call the updated orchestrator using p.procComp paths
    ApplyHexEditsToUncompressed(p, spNum);
    // ---------------- Step 7 ----------------
    wprintf(L"\n=== Step 7: Recalculate PE checksums ===\n");
    FixCheckSumsInTree(p.procRoot, exclude);
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
    if (doDriver) {
        LogInfo(L"  (c) merging driver_bins and rebuilding Driver.cab");
        CopyTreeNoOverwrite(p.iso1DriverBins, p.procDriver);

        // Windows 2000: driver.cab ships its own copy of KERNEL32.DLL. Before
        // the CAB is rebuilt, copy+replace the original (unpatched) KERNEL32.DLL
        // from the Base ISO into driver_bins so the CAB carries the same
        // untouched binary as the rest of the output (see the VI-b restore in
        // PostStep10Fixups).
        if (DetectBaseOs(p.iso1) == TargetOs::Win2000) {
            const wchar_t* names[] = { L"KERNEL32.DLL", L"kernel32.dll",
                                       L"KERNEL32.DL_", L"kernel32.dl_" };
            bool copied = false;
            for (const wchar_t* sub : { ArchDirName(arch1), L"I386", L"" }) {
                for (const wchar_t* n : names) {
                    std::wstring cand = (*sub) ? PathJoin(p.iso1, sub, n)
                                               : PathJoin(p.iso1, n);
                    if (!FileExists(cand)) continue;
                    std::wstring dst = PathJoin(p.procDriver, L"KERNEL32.DLL");
                    if (CopyFileForce(cand, dst)) {
                        LogInfo(L"  (c)   Win2000: KERNEL32.DLL copied into driver_bins -> %s", dst.c_str());
                        copied = true;
                    }
                }
                if (copied) break;
            }
            if (!copied) {
                LogWarn(L"  (c)   Win2000: KERNEL32.DLL/.DL_ not found on Base ISO - "
                        L"driver_bins may retain a patched copy.");
            }
        }

        {
            std::wstring drvOut = PathJoin(outArchDir, L"Driver.cab");
            BuildCab(p.procDriver, drvOut);
        }
    } else {
        LogInfo(L"  (c) skipped - original Driver.cab kept on the output media.");
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
    if (baseOptical || donorOptical) {
        // Files copied from mounted CD/DVD media keep FILE_ATTRIBUTE_READONLY;
        // PostStep10Fixups edits INF files (hivedef.inf / hivesys.inf) in place
        // and would otherwise fail with ERROR_ACCESS_DENIED.
        LogInfo(L"  Clearing read-only attributes on output tree (source was optical media).");
        ClearReadOnlyTree(p.output);
    }
    PostStep10Fixups(p.output, p.iso1, p.iso2, arch1, arch2,
                     gotLang1 ? lang1 : 0,
                     gotLang2 ? lang2 : 0,
                     true);  // Attach mode retired: always Replace
	ApplyHelpHtmlOverwrites(p.output, p.iso2);
    if (safeMode) {
        wprintf(L"\n=== Safe mode: restore excluded files from Base ISO ===\n");
        SafeModeRestoreExcludedFiles(p.iso1, p.output);
    }
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
//  - A section whose (trimmed, case-insensitive) name appears in `skipSections`
//    is ignored entirely (used to drop placeholder [WinntDirectories] /
//    [SourceDisksFiles] blocks from the CJK language fixup files).
// Returns the number of source sections processed.
int MergeInfSections(std::wstring& text,
                     const std::vector<RawSection>& srcSections,
                     const std::wstring& replaceSection,
                     const std::vector<std::wstring>& skipSections = {}) {
    int n = 0;
    for (const auto& src : srcSections) {
        bool skip = false;
        for (const auto& sk : skipSections) {
            if (_wcsicmp(TrimWS(src.name).c_str(), TrimWS(sk).c_str()) == 0) {
                skip = true;
                break;
            }
        }
        if (skip) {
            LogInfo(L"    skipped placeholder section [%s]", TrimWS(src.name).c_str());
            continue;
        }
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
// added as a new section). Sections whose names appear in `skipSections` are
// ignored (see MergeInfSections). Returns the number of sections merged, 0 if
// `srcPath` had no sections, or -1 on I/O error.
int MergeInfFile(const std::wstring& dstPath, const std::wstring& srcPath,
                 const std::wstring& replaceSection,
                 const std::vector<std::wstring>& skipSections = {}) {
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

    int n = MergeInfSections(dstText, sections, replaceSection, skipSections);

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

// ---------------------------------------------------------------------------
// CJK donor txtsetup.sif merge (Post-step-10, XIII)
// ---------------------------------------------------------------------------
//
// For CJK target languages the donor's txtsetup.sif has the authoritative
// list of extra source directories ([WinntDirectories]) and extra install
// files ([SourceDisksFiles]) that a Western base ISO simply does not have.
// The base's txtsetup.sif is combined with the donor's, and missing donor
// files are layered into the output arch folder without overwriting existing
// ones. The hand-authored txtsetup_<NNNN>.txt fixup files reserve
// [WinntDirectories] / [SourceDisksFiles] as *placeholders* only - their
// contents are ignored (see the skip list in the Step VII caller), so the
// real data comes from the actual donor media.

// Collect the body lines (trimmed, terminators stripped) of every [section]
// whose (trimmed, case-insensitive) name equals `name`, in order.
// Repeated section headers in INF files are legal - txtsetup.sif for CJK
// languages has several [WinntDirectories] and [SourceDisksFiles] blocks -
// so this returns the union of all their lines.
std::vector<std::wstring> CollectSectionLines(const std::wstring& text,
                                              const std::wstring& name) {
    std::vector<std::wstring> out;
    size_t pos = 0;
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
        if (IsSectionHeader(lineNoTerm, secName) &&
            _wcsicmp(TrimWS(secName).c_str(), TrimWS(name).c_str()) == 0) {
            // Advance to the next section header (or EOF) and harvest the body.
            size_t bodyStart = termEnd;
            size_t bodyEnd = text.size();
            size_t q = termEnd;
            while (q < text.size()) {
                size_t qnl = text.find_first_of(L"\r\n", q);
                size_t qEnd = (qnl == std::wstring::npos) ? text.size() : qnl;
                std::wstring qLine = text.substr(q, qEnd - q);
                std::wstring qSec;
                if (IsSectionHeader(qLine, qSec)) { bodyEnd = q; break; }
                if (qnl == std::wstring::npos) break;
                q = (text[qnl] == L'\r' && qnl + 1 < text.size() && text[qnl + 1] == L'\n')
                        ? qnl + 2 : qnl + 1;
            }
            std::wstring body = text.substr(bodyStart, bodyEnd - bodyStart);
            size_t b = 0;
            while (b < body.size()) {
                size_t bnl = body.find_first_of(L"\r\n", b);
                std::wstring bline = body.substr(b, (bnl == std::wstring::npos) ? body.size() : bnl - b);
                std::wstring t = TrimWS(bline);
                if (!t.empty()) out.push_back(t);
                if (bnl == std::wstring::npos) break;
                b = (body[bnl] == L'\r' && bnl + 1 < body.size() && body[bnl + 1] == L'\n')
                        ? bnl + 2 : bnl + 1;
            }
            pos = bodyEnd;
            continue;
        }

        if (nl == std::wstring::npos) break;
        pos = termEnd;
    }
    return out;
}

// Given collected CJK donor [SourceDisksFiles] body lines, return the subset
// that belongs to the *correct* occurrence - the one that declares the CJK NLS
// codepage table `c_10003.nls` (the marker line `c_10003.nls = 1,,,,,,,2,0,0`).
// txtsetup.sif for CJK languages has multiple [SourceDisksFiles] blocks; only
// the one carrying c_10003.nls lists the language-specific files we must add.
std::vector<std::wstring> CollectCjkSourceDisksLines(const std::wstring& text) {
    std::vector<std::wstring> out;
    size_t pos = 0;
    const std::wstring kMarker = L"c_10003.nls";

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
        size_t bodyStart = termEnd;
        bool candidate = false;
        if (IsSectionHeader(lineNoTerm, secName) &&
            _wcsicmp(TrimWS(secName).c_str(), L"SourceDisksFiles") == 0) {
            size_t bodyEnd = text.size();
            size_t q = termEnd;
            while (q < text.size()) {
                size_t qnl = text.find_first_of(L"\r\n", q);
                size_t qEnd = (qnl == std::wstring::npos) ? text.size() : qnl;
                std::wstring qLine = text.substr(q, qEnd - q);
                std::wstring qSec;
                if (IsSectionHeader(qLine, qSec)) { bodyEnd = q; break; }
                if (qnl == std::wstring::npos) break;
                q = (text[qnl] == L'\r' && qnl + 1 < text.size() && text[qnl + 1] == L'\n')
                        ? qnl + 2 : qnl + 1;
            }
            std::wstring body = text.substr(bodyStart, bodyEnd - bodyStart);
            bool isCjk = (StartsWithI(body, kMarker)) || body.find(kMarker) != std::wstring::npos;
            if (isCjk) {
                size_t b = 0;
                while (b < body.size()) {
                    size_t bnl = body.find_first_of(L"\r\n", b);
                    std::wstring bline = body.substr(b, (bnl == std::wstring::npos) ? body.size() : bnl - b);
                    std::wstring t = TrimWS(bline);
                    if (!t.empty()) out.push_back(t);
                    if (bnl == std::wstring::npos) break;
                    b = (body[bnl] == L'\r' && bnl + 1 < body.size() && body[bnl + 1] == L'\n')
                            ? bnl + 2 : bnl + 1;
                }
                return out;
            }
            pos = bodyEnd;
            continue;
        }

        if (nl == std::wstring::npos) break;
        pos = termEnd;
    }
    return out;
}

} // anonymous namespace

std::wstring ExtractOemHalFont(const std::wstring& nlsBody) {
    std::wstring targetKey = L"OemHalFont";
    size_t pos = nlsBody.find(targetKey);
    if (pos == std::wstring::npos) {
        return L"";
    }

    // Locate the equals sign after the key
    size_t eqPos = nlsBody.find(L"=", pos + targetKey.length());
    if (eqPos == std::wstring::npos) {
        return L"";
    }

    // Find where the line ends (\r or \n)
    size_t endPos = nlsBody.find_first_of(L"\r\n", eqPos);
    if (endPos == std::wstring::npos) {
        endPos = nlsBody.length();
    }

    // Extract raw value string
    std::wstring val = nlsBody.substr(eqPos + 1, endPos - (eqPos + 1));

    // Clean up spaces/whitespace surrounding the filename
    size_t first = val.find_first_not_of(L" \t");
    if (first == std::wstring::npos) return L"";
    size_t last = val.find_last_not_of(L" \t");
    
    return val.substr(first, (last - first + 1));
}

// ---------------------------------------------------------------------------
// CJK donor media merge (Post-step-10, XIII)
// ---------------------------------------------------------------------------
// Splits a section body into its individual lines (terminators stripped).
static std::vector<std::wstring> SplitBodyLines(const std::wstring& body) {
    std::vector<std::wstring> out;
    size_t pos = 0;
    while (pos < body.size()) {
        size_t nl = body.find_first_of(L"\r\n", pos);
        std::wstring line = body.substr(pos, (nl == std::wstring::npos ? body.size() : nl) - pos);
        out.push_back(line);
        if (nl == std::wstring::npos) break;
        pos = (body[nl] == L'\r' && nl + 1 < body.size() && body[nl + 1] == L'\n') ? nl + 2 : nl + 1;
    }
    return out;
}

// Append `newLines` (trimmed, terminators stripped) to the end of the section
// `secName` inside `text`. Lines whose key (text before '=') already exists in
// that section are skipped so no duplicate keys are created. If the section is
// missing it is created at EOF. Returns the number of lines appended.
static int AppendSectionLinesDedup(std::wstring& text,
                                   const std::wstring& secName,
                                   const std::vector<std::wstring>& newLines) {
    TargetSection ts;
    bool found = FindSection(text, secName, ts);

    std::set<std::wstring> existingKeys;
    if (found) {
        for (const auto& raw : SplitBodyLines(text.substr(ts.headerEnd, ts.bodyEnd - ts.headerEnd))) {
            std::wstring t = TrimWS(raw);
            if (t.empty()) continue;
            size_t eq = t.find(L'=');
            std::wstring key = (eq == std::wstring::npos) ? t : TrimWS(t.substr(0, eq));
            existingKeys.insert(ToLower(key));
        }
    }

    std::wstring append;
    int appended = 0;
    for (const auto& raw : newLines) {
        std::wstring t = TrimWS(raw);
        if (t.empty()) continue;
        size_t eq = t.find(L'=');
        std::wstring key = (eq == std::wstring::npos) ? t : TrimWS(t.substr(0, eq));
        if (existingKeys.count(ToLower(key))) continue;
        existingKeys.insert(ToLower(key));
        append += t + L"\r\n";
        appended++;
    }
    if (appended == 0 || append.empty()) return 0;

    if (found) {
        text = text.substr(0, ts.bodyEnd) + append + text.substr(ts.bodyEnd);
    } else {
        if (!text.empty() && text.back() != L'\n' && text.back() != L'\r') text += L"\r\n";
        text += L"[" + secName + L"]\r\n" + append;
    }
    return appended;
}

// (XIII) CJK donor media merge:
//   1) combine every [WinntDirectories] section of the donor txtsetup.sif and
//      append the non-duplicate lines to the output txtsetup.sif,
//   2) locate the correct [SourceDisksFiles] occurrence (the one declaring the
//      CJK NLS table `c_10003.nls`) and append its lines to the output, and
//   3) copy files from donor\<donor_arch> into output\<base_arch> without
//      overwriting existing files.
// The [WinntDirectories] / [SourceDisksFiles] blocks inside the hand-authored
// txtsetup_<NNNN>.txt fixup files are placeholders and are skipped earlier
// (see the skip list in the Step VII caller); the real data comes from here.
static void MergeCjkDonorSections(const std::wstring& outRoot,
                                  const std::wstring& iso2Root,
                                  const wchar_t* baseArchDir,
                                  const wchar_t* donorArchDir) {
    std::wstring donorSif = FindOutputFile(iso2Root, donorArchDir, L"txtsetup.sif");
    if (donorSif.empty()) donorSif = FindOutputFile(iso2Root, donorArchDir, L"TXTSETUP.SIF");
    std::wstring outSif = FindOutputFile(outRoot, baseArchDir, L"txtsetup.sif");
    if (outSif.empty()) outSif = FindOutputFile(outRoot, baseArchDir, L"TXTSETUP.SIF");

    if (donorSif.empty() || outSif.empty()) {
        LogWarn(L"  (XIII) donor/output txtsetup.sif not found (donor=%s output=%s) - CJK merge skipped.",
                donorSif.c_str(), outSif.c_str());
        return;
    }

    std::wstring donorText;
    if (!LoadInfText(donorSif, donorText)) {
        LogWarn(L"  (XIII) cannot read donor %s", donorSif.c_str());
        return;
    }
    std::wstring outText;
    if (!LoadInfText(outSif, outText)) {
        LogWarn(L"  (XIII) cannot read output %s", outSif.c_str());
        return;
    }

    // (1) [WinntDirectories] - combine ALL donor occurrences into the output.
    auto wdLines = CollectSectionLines(donorText, L"WinntDirectories");
    int nWd = 0;
    if (!wdLines.empty()) nWd = AppendSectionLinesDedup(outText, L"WinntDirectories", wdLines);
    LogInfo(L"  (XIII) [WinntDirectories]: %d new line(s) merged from donor.", nWd);

    // (2) the correct [SourceDisksFiles] (the block declaring c_10003.nls).
    auto sdfLines = CollectCjkSourceDisksLines(donorText);
    int nSdf = 0;
    if (!sdfLines.empty()) nSdf = AppendSectionLinesDedup(outText, L"SourceDisksFiles", sdfLines);
    LogInfo(L"  (XIII) [SourceDisksFiles]: %d new line(s) merged from donor.", nSdf);

    if (nWd + nSdf > 0) {
        if (!SaveInfText(outSif, outText))
            LogWarn(L"  (XIII) cannot write output %s", outSif.c_str());
    }

    // (3) copy donor arch files into the output base arch (no overwrite).
    std::wstring donorArchAbs = PathJoin(iso2Root, donorArchDir);
    std::wstring outArchAbs   = PathJoin(outRoot, baseArchDir);
    if (DirExists(donorArchAbs)) {
        LogInfo(L"  (XIII) copying missing files from %s -> %s (no overwrite).",
                donorArchAbs.c_str(), outArchAbs.c_str());
        CopyTreeNoOverwrite(donorArchAbs, outArchAbs);
    } else {
        LogWarn(L"  (XIII) donor arch folder %s not found - file copy skipped.", donorArchAbs.c_str());
    }
}

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
        LogInfo(L"  (III) skipped (no donor lang detected).");
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

    // (VI-c) Windows 2000 only: on Win2000 media, DSSENH.DLL and RSAENH.DLL
    // are instead named DSSBASE.DLL and RSABASE.DLL respectively. Copy these
    // original files from the Base ISO into the equivalent output location
    // so the CSP DLLs remain unpatched, matching the DSSENH/RSAENH handling
    // above on later OS versions. INITPKI.DLL needs no special handling on
    // Windows 2000 and is left as produced by the earlier pipeline steps.
    if (DetectBaseOs(iso1Root) == TargetOs::Win2000) {
        struct BaseFile { const wchar_t* upper; const wchar_t* lower; const wchar_t* label; };
        const BaseFile baseFiles[] = {
            { L"DSSBASE.DLL", L"dssbase.dll", L"dssbase" },
            { L"RSABASE.DLL", L"rsabase.dll", L"rsabase" },
        };
        for (const auto& bf : baseFiles) {
            const wchar_t* names[] = { bf.upper, bf.lower };
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
                        LogInfo(L"  (VI-c) Win2000: %s restored unpatched from Base -> %s",
                                bf.label, dst.c_str());
                        restored = true;
                    }
                }
            }
            if (!restored) {
                LogWarn(L"  (VI-c) Win2000: %s not found on Base ISO - "
                        L"output may contain a resource-patched copy.", bf.label);
            }
        }
    }

    // ---------------------------------------------------------------------
    // (VII)-(X) Complex-script language fixups: Chinese Simp./Trad., Korean,
    // Japanese, Arabic, and Hebrew.
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
                        MergeInfFile(dstFile, srcFile, L"nls",
                                     {L"WinntDirectories", L"SourceDisksFiles"});
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

            // (XIII) CJK donor media merge: combine the donor txtsetup.sif's
            //   [WinntDirectories] / [SourceDisksFiles] sections into the
            //   output and copy missing donor arch files (no overwrite).
            //   Only meaningful for CJK languages where the Western base ISO
            //   lacks the language-specific directory and file listings.
            {
                const wchar_t* donorArchDir = ArchDirName(donorArch);
                MergeCjkDonorSections(outRoot, iso2Root, archDir, donorArchDir);
            }

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
            // First, locate the setup file configuration payload
            std::wstring sifPath = FindOutputFile(outRoot, archDir, L"txtsetup.sif");
            if (sifPath.empty()) {
                sifPath = FindOutputFile(outRoot, archDir, L"TXTSETUP.SIF");
            }

            if (sifPath.empty()) {
                LogWarn(L"  (XII) txtsetup.sif not found under %s", outRoot.c_str());
            } else {
                bool nlsUpdated = false;
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
                        nlsUpdated = true; // Mark true to allow font processing
                    }
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
                        nlsUpdated = true;
                    }
                }

                // If the NLS infrastructure is active/ready, append structural font mappings
                // (XII) Append font file mapping to [SourceDisksFiles] inside txtsetup.sif
                if (nlsUpdated) {
                    std::wstring fontFilename;
                
                    // Try extracting directly from the matching NlsSectionForLang text block
                    if (!nlsBody.empty()) {
                        fontFilename = ExtractOemHalFont(nlsBody);
                    }
                
                    // CJK Layout or extraction fallback logic
                    if (fontFilename.empty()) {
                        std::wstring langTag = CjkLangTag(newLang);
                        if (!langTag.empty()) {
                            fontFilename = L"vgaoem.fon"; // Standard CJK setup font fallback
                        } else {
                            fontFilename = L"vgaoem.fon"; // Generic Western fallback
                        }
                    }
                
                    LogInfo(L"  (XII) Appending font file mappings (%s) to [SourceDisksFiles] for %s...", 
                            fontFilename.c_str(), LangIdName(newLang));
                    
                    AddFontToSourceDisksFiles(sifPath, fontFilename);
                }
            }
        }
    } else {
        LogInfo(L"  (VII-XII) skipped (no donor lang detected).");
    }

    return true;
}
