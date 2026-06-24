// ResourceUpdate.cpp - BeginUpdateResource / UpdateResource / EndUpdateResource.
#include "ResourceUpdate.h"

#include <set>
#include <fstream>

namespace {

// Parse the filename-suffix tail produced by ResourceExtract:
//   <basename>_type<T>_id<I>_lang<L>.bin
// On success returns true and fills outType/outName/outLang.
//
// outTypeIsInt / outNameIsInt indicate whether <T>/<I> are integers (true)
// or string names (false).
bool ParseSuffix(const std::wstring& suffix,   // everything after "<basename>_"
                 std::wstring& outTypeStr, bool& outTypeIsInt, WORD& outTypeInt,
                 std::wstring& outNameStr, bool& outNameIsInt, WORD& outNameInt,
                 WORD& outLang) {
    // Remove ".bin"
    if (!EndsWithI(suffix, L".bin")) return false;
    std::wstring s = suffix.substr(0, suffix.size() - 4);

    // Expect "type"<T> "_id"<I> "_lang"<L>
    if (!StartsWithI(s, L"type")) return false;
    s.erase(0, 4);

    size_t pId = s.find(L"_id");
    if (pId == std::wstring::npos) return false;
    std::wstring tField = s.substr(0, pId);
    s.erase(0, pId + 3);

    size_t pLang = s.find(L"_lang");
    if (pLang == std::wstring::npos) return false;
    std::wstring iField = s.substr(0, pLang);
    s.erase(0, pLang + 5);

    std::wstring lField = s; // remainder is the language

    // Parse fields
    auto tryInt = [](const std::wstring& v, WORD& out) {
        if (v.empty()) return false;
        for (wchar_t c : v) if (c < L'0' || c > L'9') return false;
        unsigned long n = wcstoul(v.c_str(), nullptr, 10);
        if (n > 0xFFFF) return false;
        out = (WORD)n;
        return true;
    };

    outTypeIsInt = tryInt(tField, outTypeInt);
    outTypeStr   = tField;
    outNameIsInt = tryInt(iField, outNameInt);
    outNameStr   = iField;
    if (!tryInt(lField, outLang)) return false;
    return true;
}

bool IsExcludedType(WORD t) {
    switch (t) {
        case 1:  case 2:  case 3:
        case 12: case 14: case 16:
        case 24:
            return true;
    }
    return false;
}

bool ReadFileBytes(const std::wstring& path, std::vector<BYTE>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    if (sz.QuadPart > 0x7FFFFFFF) { CloseHandle(h); return false; }
    out.resize((size_t)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &rd, nullptr);
    CloseHandle(h);
    return ok && rd == out.size();
}

// Apply every matching .bin in resourceFolder to filepath via Begin/UpdateResource.
// Returns:
//    1  -> at least one resource updated
//    0  -> file processed but nothing updated
//   -1  -> hard failure (Begin/EndUpdateResource failed)
int UpdateOne(const std::wstring& filepath, const std::wstring& resourceFolder) {
    std::wstring base = GetFileNameFromPath(filepath);
    std::wstring prefix = base + L"_";

    HANDLE hUpd = BeginUpdateResourceW(filepath.c_str(), FALSE);
    if (!hUpd) {
        LogError(L"BeginUpdateResource failed (%lu): %s", GetLastError(), filepath.c_str());
        return -1;
    }

    int updated = 0;

    // Iterate the resource folder
    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(resourceFolder, L"*.bin");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (!StartsWithI(name, prefix)) continue;
            std::wstring suffix = name.substr(prefix.size());

            std::wstring typeStr, nameStr;
            bool typeIsInt, nameIsInt;
            WORD typeInt = 0, nameInt = 0, lang = 0;
            if (!ParseSuffix(suffix, typeStr, typeIsInt, typeInt,
                                     nameStr, nameIsInt, nameInt, lang)) {
                LogWarn(L"  Skipping malformed: %s", name.c_str());
                continue;
            }

            // Apply exclusion to integer types we know about
            if (typeIsInt && IsExcludedType(typeInt)) continue;

            std::wstring resPath = PathJoin(resourceFolder, name);
            std::vector<BYTE> data;
            if (!ReadFileBytes(resPath, data)) {
                LogError(L"  Could not read %s", resPath.c_str());
                continue;
            }

            LPCWSTR typeArg = typeIsInt ? MAKEINTRESOURCEW(typeInt) : typeStr.c_str();
            LPCWSTR nameArg = nameIsInt ? MAKEINTRESOURCEW(nameInt) : nameStr.c_str();

            if (!UpdateResourceW(hUpd, typeArg, nameArg, lang,
                                 data.empty() ? nullptr : data.data(),
                                 (DWORD)data.size())) {
                LogError(L"  UpdateResource failed (%lu) for %s", GetLastError(), name.c_str());
                continue;
            }
            updated++;
            LogDebug(L"  ~ %s (%llu bytes)", name.c_str(), (unsigned long long)data.size());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    if (!EndUpdateResourceW(hUpd, FALSE)) {
        LogError(L"EndUpdateResource failed (%lu): %s", GetLastError(), filepath.c_str());
        return -1;
    }
    return updated > 0 ? 1 : 0;
}

void WalkAndProcess(const std::wstring& inputFolder,
                    const std::wstring& resourceFolder,
                    const std::wstring& outputFolder,
                    bool skipEmpty,
                    int& totalProcessed,
                    int& totalUpdated) {
    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(inputFolder, L"*");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = PathJoin(inputFolder, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // recurse, mirroring the structure under outputFolder
            WalkAndProcess(full, resourceFolder,
                           PathJoin(outputFolder, fd.cFileName),
                           skipEmpty, totalProcessed, totalUpdated);
            continue;
        }
        if (!IsPEFile(full)) continue;

        totalProcessed++;
        std::wstring outPath = PathJoin(outputFolder, fd.cFileName);
        if (!CopyFileForce(full, outPath)) continue;

        int rc = UpdateOne(outPath, resourceFolder);
        if (rc > 0) {
            totalUpdated++;
            LogInfo(L"Updated: %s", outPath.c_str());
        } else if (rc == 0 && skipEmpty) {
            DeleteFileW(outPath.c_str());
            LogDebug(L"  no resources matched, dropped: %s", fd.cFileName);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

} // namespace

bool IsPEFile(const std::wstring& filepath) {
    std::wstring lower = ToLower(GetFileNameFromPath(filepath));
    bool extOk =
        EndsWithI(lower, L".exe") || EndsWithI(lower, L".dll") ||
        EndsWithI(lower, L".sys") || EndsWithI(lower, L".ocx") ||
        EndsWithI(lower, L".cpl") || EndsWithI(lower, L".mui");
    if (!extOk) return false;

    HANDLE h = CreateFileW(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char hdr[2] = {0,0};
    DWORD rd = 0;
    ReadFile(h, hdr, 2, &rd, nullptr);
    CloseHandle(h);
    return rd == 2 && hdr[0] == 'M' && hdr[1] == 'Z';
}

bool ReplaceResources(const std::wstring& inputFolder,
                      const std::wstring& resourceFolder,
                      const std::wstring& outputFolder,
                      bool skipEmpty) {
    LogInfo(L"Starting resource replacement...");
    LogInfo(L"  in:  %s", inputFolder.c_str());
    LogInfo(L"  res: %s", resourceFolder.c_str());
    LogInfo(L"  out: %s", outputFolder.c_str());

    if (!DirExists(inputFolder)) {
        LogError(L"Input folder does not exist: %s", inputFolder.c_str());
        return false;
    }
    if (!DirExists(resourceFolder)) {
        LogWarn(L"Resource folder does not exist: %s", resourceFolder.c_str());
    }
    MakeDirs(outputFolder);

    int processed = 0, updated = 0;
    WalkAndProcess(inputFolder, resourceFolder, outputFolder, skipEmpty,
                   processed, updated);

    LogInfo(L"Resource replacement done: %d processed, %d updated.", processed, updated);
    return true;
}
