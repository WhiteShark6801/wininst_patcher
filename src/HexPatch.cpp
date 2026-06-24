// HexPatch.cpp
#include "HexPatch.h"

std::vector<BYTE> HexBytes(const wchar_t* s) {
    std::vector<BYTE> out;
    auto nyb = [](wchar_t c, int& v) -> bool {
        if (c >= L'0' && c <= L'9') { v = c - L'0';      return true; }
        if (c >= L'a' && c <= L'f') { v = c - L'a' + 10; return true; }
        if (c >= L'A' && c <= L'F') { v = c - L'A' + 10; return true; }
        return false;
    };
    int hi = -1;
    for (const wchar_t* p = s; *p; ++p) {
        if (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n') continue;
        int v;
        if (!nyb(*p, v)) { out.clear(); return out; }
        if (hi < 0) hi = v;
        else { out.push_back((BYTE)((hi << 4) | v)); hi = -1; }
    }
    if (hi >= 0) { out.clear(); }   // odd-length: invalid
    return out;
}

int HexPatchFile(const std::wstring& path,
                 const std::vector<BYTE>& from,
                 const std::vector<BYTE>& to) {
    if (from.size() != to.size() || from.empty()) {
        LogError(L"HexPatchFile: bad pattern lengths (from=%zu, to=%zu)",
                 from.size(), to.size());
        return -1;
    }

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LogWarn(L"  HexPatch: cannot open %s (%lu)", path.c_str(), GetLastError());
        return -1;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > 0x7FFFFFFF) {
        LogWarn(L"  HexPatch: file too large or unreadable: %s", path.c_str());
        CloseHandle(h);
        return -1;
    }
    std::vector<BYTE> buf((size_t)sz.QuadPart);
    DWORD rd = 0;
    if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd != buf.size()) {
        LogWarn(L"  HexPatch: read failed: %s", path.c_str());
        CloseHandle(h);
        return -1;
    }

    int hits = 0;
    if (buf.size() >= from.size()) {
        const BYTE* needle = from.data();
        size_t nlen = from.size();
        // Naive scan; the inputs aren't large (a few MB at most).
        for (size_t i = 0; i + nlen <= buf.size(); ++i) {
            if (memcmp(buf.data() + i, needle, nlen) != 0) continue;
            memcpy(buf.data() + i, to.data(), nlen);
            hits++;
            i += nlen - 1;  // skip past replacement to avoid overlapping rematch
        }
    }

    if (hits > 0) {
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        DWORD wr = 0;
        if (!WriteFile(h, buf.data(), (DWORD)buf.size(), &wr, nullptr) || wr != buf.size()) {
            LogError(L"  HexPatch: write failed: %s", path.c_str());
            CloseHandle(h);
            return -1;
        }
    }
    CloseHandle(h);
    return hits;
}
