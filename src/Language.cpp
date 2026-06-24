// Language.cpp
#include "Language.h"

#include <fstream>
#include <string>

namespace {

struct LangEntry { DWORD id; const wchar_t* name; };

// Mapping from the spec.
static const LangEntry kLangTable[] = {
    { 0x0401, L"Arabic"               },
    { 0x0405, L"Czech"                },
    { 0x0406, L"Danish"               },
    { 0x0407, L"German"               },
    { 0x0408, L"Greek"                },
    { 0x0409, L"US English"           },
    { 0x0c0a, L"Spanish"              },
    { 0x040b, L"Finnish"              },
    { 0x040c, L"French"               },
    { 0x040d, L"Hebrew"               },
    { 0x040e, L"Hungarian"            },
    { 0x0410, L"Italian"              },
    { 0x0411, L"Japanese"             },
    { 0x0412, L"Korean"               },
    { 0x0413, L"Dutch"                },
    { 0x0414, L"Norwegian"            },
    { 0x0415, L"Polish"               },
    { 0x0416, L"Portuguese (Brazil)"  },
    { 0x0816, L"Portuguese (Portugal)"},
    { 0x0419, L"Russian"              },
    { 0x041d, L"Swedish"              },
    { 0x041f, L"Turkish"              },
    { 0x0804, L"Chinese (Simp.)"      },
    { 0x0404, L"Chinese (Trad.)"      },
};

bool LooksLikeIntlLocaleLine(const std::wstring& line, std::wstring& outValue) {
    // The line we care about is something like:
    //   HKLM,"SYSTEM\...\Nls\Language","Default",0x00000000,"00000409"
    // ...where the "INTL_LOCALE" token also appears earlier in the same hivedef
    // group of entries. Across hivedef.inf variants we've seen:
    //
    //   "...","INTL_LOCALE",0x... ,"00000409"
    //   ;Default = INTL_LOCALE
    //   HKLM,...,INTL_LOCALE,...,...
    //
    // Strategy: any line containing the literal "INTL_LOCALE", case-insensitive,
    // that also has a quoted 8-hex-digit value somewhere on it - extract it.
    std::wstring upper = ToUpper(line);
    if (upper.find(L"INTL_LOCALE") == std::wstring::npos) return false;

    // Look for a quoted run of 8 hex chars.
    size_t i = 0;
    while (i < line.size()) {
        if (line[i] == L'"') {
            size_t end = line.find(L'"', i + 1);
            if (end == std::wstring::npos) break;
            std::wstring tok = line.substr(i + 1, end - i - 1);
            if (tok.size() == 8) {
                bool allHex = true;
                for (wchar_t c : tok) {
                    if (!((c >= L'0' && c <= L'9') ||
                          (c >= L'a' && c <= L'f') ||
                          (c >= L'A' && c <= L'F'))) { allHex = false; break; }
                }
                if (allHex) { outValue = tok; return true; }
            }
            i = end + 1;
        } else {
            i++;
        }
    }
    return false;
}

// Locate hivedef.inf under a media root. Standard location is
// <media>\I386\HIVEDEF.IN_  (compressed) or HIVEDEF.INF in service-pack
// integrated images. On AMD64/IA64 it's mirrored under that arch dir.
std::wstring FindHivedef(const std::wstring& mediaRoot) {
    const wchar_t* subs[] = { L"I386", L"AMD64", L"IA64", L"" };
    const wchar_t* names[] = {
        L"hivedef.inf", L"HIVEDEF.INF",
        L"hivedef.in_", L"HIVEDEF.IN_"
    };
    for (const wchar_t* sub : subs) {
        std::wstring base = (*sub) ? PathJoin(mediaRoot, sub) : mediaRoot;
        for (const wchar_t* n : names) {
            std::wstring p = PathJoin(base, n);
            if (FileExists(p)) return p;
        }
    }
    return L"";
}

bool ReadAllText(const std::wstring& path, std::wstring& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    if (sz.QuadPart > 0x4000000) { CloseHandle(h); return false; } // 64 MB sanity
    std::string raw((size_t)sz.QuadPart, '\0');
    DWORD rd = 0;
    BOOL ok = ReadFile(h, raw.data(), (DWORD)raw.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok) return false;

    // Detect UTF-16 LE BOM
    if (raw.size() >= 2 && (BYTE)raw[0] == 0xFF && (BYTE)raw[1] == 0xFE) {
        out.assign((const wchar_t*)(raw.data() + 2),
                   (raw.size() - 2) / sizeof(wchar_t));
        return true;
    }
    // Otherwise treat as ANSI / UTF-8
    int n = MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), nullptr, 0);
    out.resize(n);
    MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), &out[0], n);
    return true;
}

} // namespace

bool DetectMediaLangId(const std::wstring& mediaRoot, DWORD& outLangId) {
    std::wstring inf = FindHivedef(mediaRoot);
    if (inf.empty()) {
        LogWarn(L"hivedef.inf not found under %s", mediaRoot.c_str());
        return false;
    }

    // hivedef.in_ is a CAB-compressed copy. Expand to a temp file.
    std::wstring textPath = inf;
    std::wstring scratch;
    if (EndsWithI(inf, L".in_")) {
        wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
        scratch = PathJoin(tmp, L"wininst_hivedef_" +
                                std::to_wstring(GetCurrentProcessId()) + L"_" +
                                std::to_wstring(GetTickCount()) + L".inf");
        std::wstring cmd = L"expand.exe \"" + inf + L"\" \"" + scratch + L"\"";
        if (RunCommand(cmd) != 0 || !FileExists(scratch)) {
            LogWarn(L"Could not expand %s", inf.c_str());
            return false;
        }
        textPath = scratch;
    }

    std::wstring text;
    if (!ReadAllText(textPath, text)) {
        if (!scratch.empty()) DeleteFileW(scratch.c_str());
        return false;
    }
    if (!scratch.empty()) DeleteFileW(scratch.c_str());

    // Walk lines.
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find_first_of(L"\r\n", pos);
        std::wstring line = text.substr(pos, (nl == std::wstring::npos ? text.size() : nl) - pos);
        std::wstring hex;
        if (LooksLikeIntlLocaleLine(line, hex)) {
            outLangId = wcstoul(hex.c_str(), nullptr, 16);
            LogInfo(L"  %s : INTL_LOCALE = %s -> 0x%X (%lu) - %s",
                    inf.c_str(), hex.c_str(), outLangId, outLangId,
                    LangIdName(outLangId));
            return true;
        }
        if (nl == std::wstring::npos) break;
        pos = nl;
        while (pos < text.size() && (text[pos] == L'\r' || text[pos] == L'\n')) pos++;
    }
    LogWarn(L"INTL_LOCALE not found in %s", inf.c_str());
    return false;
}

const wchar_t* LangIdName(DWORD langId) {
    for (const auto& e : kLangTable) {
        if (e.id == langId) return e.name;
    }
    return L"Unknown";
}

int RenameBinLangSuffix(const std::wstring& folder, DWORD from, DWORD to) {
    if (from == to) return 0;
    if (!DirExists(folder)) return 0;

    wchar_t fromBuf[16], toBuf[16];
    swprintf_s(fromBuf, L"_lang%lu.bin", from);
    swprintf_s(toBuf,   L"_lang%lu.bin", to);
    std::wstring fromSuf = fromBuf;
    std::wstring toSuf   = toBuf;

    int renamed = 0;
    WIN32_FIND_DATAW fd = {};
    std::wstring pattern = PathJoin(folder, L"*.bin");
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        std::wstring name = fd.cFileName;
        if (!EndsWithI(name, fromSuf)) continue;
        std::wstring stem = name.substr(0, name.size() - fromSuf.size());
        std::wstring newName = stem + toSuf;
        std::wstring oldPath = PathJoin(folder, name);
        std::wstring newPath = PathJoin(folder, newName);

        // If a same-named target exists, blow it away first - the new one wins.
        if (FileExists(newPath)) DeleteFileW(newPath.c_str());

        if (MoveFileW(oldPath.c_str(), newPath.c_str())) {
            renamed++;
        } else {
            LogWarn(L"rename failed (%lu): %s -> %s",
                    GetLastError(), name.c_str(), newName.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return renamed;
}
