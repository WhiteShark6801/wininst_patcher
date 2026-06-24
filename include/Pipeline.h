// Pipeline.h - Top-level orchestration
#pragma once
#include "Common.h"

struct Paths {
    std::wstring iso1;            // first installation media root (target to be patched)
    std::wstring iso2;            // second installation media root (resource source)
    std::wstring output;          // final output dir

    std::wstring root;            // working root (created next to output)
    std::wstring iso1Bins;        // <root>\ISO_1
    std::wstring iso1CompBins;
    std::wstring iso1UncompBins;
    std::wstring iso1DriverBins;
    std::wstring iso1ServicepackBins;
    std::wstring iso1WowBins;

    std::wstring iso2Bins;        // <root>\ISO_2
    std::wstring iso2CompBins;
    std::wstring iso2UncompBins;
    std::wstring iso2DriverBins;
    std::wstring iso2ServicepackBins;
    std::wstring iso2WowBins;

    std::wstring resources;       // <root>\Resources

    std::wstring procRoot;        // <root>\ISO_1_processed
    std::wstring procComp;
    std::wstring procUncomp;
    std::wstring procDriver;
    std::wstring procServicepack;
    std::wstring procWow;
};

bool DetectArch(const std::wstring& mediaRoot, Arch& outArch);

// True if the media has any of SP1.CAB..SP4.CAB at root.
bool HasServicePackCab(const std::wstring& mediaRoot,
                       std::wstring& outCabFile, int& outSpNum);

// Run the full pipeline. Returns true on success.
bool RunPipeline();

// Re-stamp the PE checksum on every PE file in dir (recursive).
bool FixCheckSumsInTree(const std::wstring& dir);
