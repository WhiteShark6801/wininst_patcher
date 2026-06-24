// Language.h - hivedef.inf parsing, langID lookup, .bin renaming
#pragma once
#include "Common.h"

// Find hivedef.inf on a media root and parse out the INTL_LOCALE entry.
// Returns true on success and fills outLangId with the decoded DWORD
// (e.g. "00000409" -> 0x409 == 1033).
bool DetectMediaLangId(const std::wstring& mediaRoot, DWORD& outLangId);

// Returns a friendly display name (e.g. "US English") for the langID, or
// L"Unknown" if not in the table.
const wchar_t* LangIdName(DWORD langId);

// Rename every .bin in `folder` whose filename ends with "_lang<from>.bin"
// to "_lang<to>.bin" (case-insensitive).  Returns the count of files renamed.
int RenameBinLangSuffix(const std::wstring& folder, DWORD from, DWORD to);
