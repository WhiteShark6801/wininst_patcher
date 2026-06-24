// HexPatch.h - byte-pattern find-and-replace for binaries
#pragma once
#include "Common.h"

// Replace every occurrence of `from` with `to` in `path`. The two patterns
// must be the same length (no insertion/deletion). Returns the number of
// replacements performed, or -1 on I/O error.
int HexPatchFile(const std::wstring& path,
                 const std::vector<BYTE>& from,
                 const std::vector<BYTE>& to);

// Build a pattern from a hex literal like "558BEC8B452C". Whitespace ignored.
// Returns empty vector if the string isn't valid hex (odd length, bad chars).
std::vector<BYTE> HexBytes(const wchar_t* s);
