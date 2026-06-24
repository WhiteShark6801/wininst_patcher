// ResourceExtract.cpp - Walks PE resource directory via Win32 enum APIs.
#include "ResourceExtract.h"

#include <set>

namespace {

struct ExtractCtx {
    HMODULE       mod;
    std::wstring  outFolder;
    std::wstring  baseName;   // e.g. "msgina.dll"
};

// Resource types we always exclude (matches the spec).
//  RT_BITMAP        = 2
//  RT_ICON          = 3
//  RT_CURSOR        = 1
//  RT_GROUP_ICON    = 14
//  RT_GROUP_CURSOR  = 12
//  RT_VERSION       = 16
//  RT_MANIFEST      = 24
bool IsExcludedType(LPCWSTR type) {
    if (IS_INTRESOURCE(type)) {
        WORD t = (WORD)(uintptr_t)type;
        switch (t) {
            case 1:  case 2:  case 3:
            case 12: case 14: case 16:
            case 24:
                return true;
        }
        return false;
    }
    // String types are uncommon; nothing to filter by name here.
    return false;
}

// Format type/name/lang the way the Python script does:
//   integer -> "<num>"  (e.g. type6, id101, lang1033)
//   string  -> the literal string
std::wstring FormatId(LPCWSTR id) {
    if (IS_INTRESOURCE(id)) {
        wchar_t buf[16];
        swprintf_s(buf, L"%u", (unsigned)(uintptr_t)id);
        return buf;
    }
    return id;
}

// Sanitise: strip path separators and other things illegal in filenames.
std::wstring SanitiseForFilename(std::wstring s) {
    for (auto& c : s) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' ||
            c == L'?'  || c == L'"' || c == L'<' || c == L'>' ||
            c == L'|') c = L'_';
    }
    return s;
}

BOOL CALLBACK EnumLangProc(HMODULE /*hMod*/, LPCWSTR type, LPCWSTR name,
                           WORD lang, LONG_PTR p) {
    auto* ctx = reinterpret_cast<ExtractCtx*>(p);

    HRSRC hRes = FindResourceExW(ctx->mod, type, name, lang);
    if (!hRes) return TRUE;
    DWORD size = SizeofResource(ctx->mod, hRes);
    if (size == 0) return TRUE;
    HGLOBAL hG = LoadResource(ctx->mod, hRes);
    if (!hG) return TRUE;
    LPVOID data = LockResource(hG);
    if (!data) return TRUE;

    std::wstring fn = ctx->baseName + L"_type" + SanitiseForFilename(FormatId(type))
                                    + L"_id"   + SanitiseForFilename(FormatId(name))
                                    + L"_lang" + std::to_wstring(lang) + L".bin";
    std::wstring full = PathJoin(ctx->outFolder, fn);

    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LogError(L"Cannot create %s (%lu)", full.c_str(), GetLastError());
        return TRUE;
    }
    DWORD wrote = 0;
    WriteFile(h, data, size, &wrote, nullptr);
    CloseHandle(h);
    LogDebug(L"  + %s (%lu bytes)", fn.c_str(), size);
    return TRUE;
}

BOOL CALLBACK EnumNameProc(HMODULE hMod, LPCWSTR type, LPWSTR name, LONG_PTR p) {
    EnumResourceLanguagesW(hMod, type, name, EnumLangProc, p);
    return TRUE;
}

BOOL CALLBACK EnumTypeProc(HMODULE hMod, LPWSTR type, LONG_PTR p) {
    if (IsExcludedType(type)) return TRUE;
    EnumResourceNamesW(hMod, type, EnumNameProc, p);
    return TRUE;
}

} // namespace

bool ExtractResources(const std::wstring& peFile, const std::wstring& outFolder) {
    LogInfo(L"Extracting resources from: %s", peFile.c_str());

    HMODULE mod = LoadLibraryExW(peFile.c_str(), nullptr,
                                 LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!mod) {
        // Fall back to plain DATAFILE flag (older OS / non-DLL files)
        mod = LoadLibraryExW(peFile.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
    }
    if (!mod) {
        LogWarn(L"  could not load (%lu): %s", GetLastError(), peFile.c_str());
        return false;
    }

    if (!MakeDirs(outFolder)) {
        FreeLibrary(mod);
        return false;
    }

    ExtractCtx ctx;
    ctx.mod       = mod;
    ctx.outFolder = outFolder;
    ctx.baseName  = GetFileNameFromPath(peFile);

    EnumResourceTypesW(mod, EnumTypeProc, (LONG_PTR)&ctx);

    FreeLibrary(mod);
    return true;
}

bool ExtractResourcesFromFolder(const std::wstring& inputFolder,
                                const std::wstring& outFolder) {
    if (!DirExists(inputFolder)) {
        LogError(L"Input folder does not exist: %s", inputFolder.c_str());
        return false;
    }
    auto files = ListFilesByExt(inputFolder, {});  // all files
    for (const auto& f : files) {
        // Only PE-extension files. Same set as ReplaceFinal.is_pe_file
        std::wstring lower = ToLower(GetFileNameFromPath(f));
        bool ok =
            EndsWithI(lower, L".exe") || EndsWithI(lower, L".dll") ||
            EndsWithI(lower, L".sys") || EndsWithI(lower, L".ocx") ||
            EndsWithI(lower, L".cpl") || EndsWithI(lower, L".mui");
        if (!ok) continue;
        ExtractResources(f, outFolder);
    }
    return true;
}
