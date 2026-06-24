// CabUtil.h - CAB extract / per-file compress / multi-file CAB build
#pragma once
#include "Common.h"

// Extract a CAB to a folder. Uses the system `expand.exe` (always present on
// Windows / WinPE).
bool ExtractCab(const std::wstring& cabFile, const std::wstring& outDir);

// Compress all files in `srcDir` into `dstDir` such that every file 'foo.dll'
// becomes 'foo.dl_' (last char of the extension replaced with '_').
// Uses `makecab` once per file.
bool CompressFolderPerFile(const std::wstring& srcDir, const std::wstring& dstDir);

// Build a single CAB at `cabPath` containing every file in `srcDir`
// (top level, non-recursive — matches Driver.cab / SP*.CAB layout).
// Files inside are stored with their bare basenames.
bool BuildCab(const std::wstring& srcDir,
              const std::wstring& cabPath);
