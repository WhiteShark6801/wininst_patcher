// ResourceUpdate.h - PE resource replacement (replaces ReplaceFinal.py)
#pragma once
#include "Common.h"

// Returns true if the file is a PE-image-extension file with an MZ header.
bool IsPEFile(const std::wstring& filepath);

// Walk inputFolder recursively. For each PE file:
//   1. Copy to outputFolder (preserving relative path)
//   2. Open with BeginUpdateResource and overwrite every resource that has a
//      matching .bin in resourceFolder (filename-prefixed by the PE file's
//      basename).  Excluded types: 1,2,3,12,14,16,24.
// If skipEmpty is true and no resources were updated, the output copy is
// removed afterwards.
bool ReplaceResources(const std::wstring& inputFolder,
                      const std::wstring& resourceFolder,
                      const std::wstring& outputFolder,
                      bool skipEmpty);
