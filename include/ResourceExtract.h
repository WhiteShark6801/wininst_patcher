// ResourceExtract.h - PE resource extraction (replaces extract.py)
#pragma once
#include "Common.h"

// Extract resources from one PE file to outFolder.
// Filename format produced (matches the Python script):
//   <basename.ext>_type<TYPE>_id<ID>_lang<LANG>.bin
// where TYPE/ID may be either an integer or a string name.
//
// Skips: Manifest (24), Bitmap (2), GroupIcon(14)+Icon(3),
//        GroupCursor(12)+Cursor(1), Version Info (16).
bool ExtractResources(const std::wstring& peFile, const std::wstring& outFolder);

// Walk every PE file in inputFolder (non-recursive) and extract all of them.
bool ExtractResourcesFromFolder(const std::wstring& inputFolder,
                                const std::wstring& outFolder);
