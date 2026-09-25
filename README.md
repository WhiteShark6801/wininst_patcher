# wininst_patcher

Integrate multilingual resources into Windows NT 5.x (Windows 2000, XP, Server 2003) installation media.

**wininst_patcher** is a tool for cross-stamping Windows installation discs with resources from a donor language pack. It extracts binaries from two ISO images (base and resource donor), patches PE files with localized strings, dialogs, and resources, re-stamps checksums to pass signature validation, and outputs a patched media tree ready for repackaging into a bootable ISO.

---

## Features

- **Multi-architecture support**: x86 (I386), x64 (AMD64), IA64 (Itanium), DEC Alpha (ALPHA), and Alpha AXP 64-bit (AXP64)
- **Language resource extraction**: Automatically extracts .RES/.MUI resources from PE files
- **PE resource patching**: Merges donor language resources into base ISO binaries
- **PE checksum re-stamping**: Recalculates and updates PE headers to pass signature checks
- **Automatic layout detection**: Detects Windows 2000, XP, and Server 2003 variants
- **Cross-architecture support**: Handles WOW64 (32-bit on 64-bit) binary mapping
- **Service pack integration**: Merges SP*.CAB files during patching
- **CJK donor-media merge**: For Chinese/Japanese/Korean targets, combines the donor `txtsetup.sif` `[WinntDirectories]`/`[SourceDisksFiles]` sections into the output and copies missing donor arch files (no overwrite)
- **Logging**: Comprehensive timestamped logs for debugging failed runs

---

## Requirements

### System
- **OS**: Windows NT 5.0+ (Windows 2000, XP, 2003, etc.)
- **Architecture**: x86, x64, or IA64
- **Disk space**: ≥ 2 GB free (for staging directories)

### Build
- **Visual Studio**: C++ build tools (MSVC 2015+)
  - x86 or x64 Native Tools Command Prompt
  - C++17 standard support

### Media
- **Base ISO** (extracted directory or mounted CD/DVD)
  - Windows 2000, XP, or Server 2003 installation media
  - Must have I386, AMD64, or IA64 subdirectory
- **Resource ISO** (extracted directory or mounted CD/DVD)
  - Same OS, different language variant
  - Should have matching architecture

> Mounted CD/DVD drives can be used directly as Base and/or Resource media. The
> tool reads them read-only (no copies of the full media are needed, saving
> 700–800 MB of staging space) and clears the read-only attribute that CD/DVD
> files carry from the output folder before the post-cleanup fixups.

---

## Build

### Quick Start
```batch
# Open x86 or x64 Native Tools Command Prompt for Visual Studio as Administrator
x86 Native Tools Command Prompt for VS
cd wininst_patcher
build.cmd
```

Output: `build\wininst_patcher.exe`

### Build Details
The `build.cmd` script:
- Compiles all source files with C++17 support
- Links against `shlwapi.lib`, `imagehlp.lib`, `user32.lib`, `advapi32.lib`
- Produces a single-file console executable
- Fails if `VCINSTALLDIR` environment variable is not set (i.e., not run from a VS prompt)

---

## Usage

### Basic Workflow

1. **Prepare both ISOs** (extract to a writable directory, or mount the CD/DVD)
   ```
   ISO 1: E:\BaseISO       (Windows XP English)
   ISO 2: E:\DonorISO      (Windows XP French)
   ```

2. **Run the patcher**
   ```batch
   wininst_patcher.exe
   ```

3. **Answer prompts**
   ```
   Path to BASE ISO (target media root): E:\BaseISO
   Path to RESOURCE ISO (donor media root): E:\DonorISO
   Path to output folder: E:\Output
   
   Detected:
     Base ISO: 0x0409 (English - United States)
     Resource ISO: 0x040c (French)
   
   Mode [S/F]: F
   ```

4. **Wait** (15–20 minutes, depending on media size)

5. **Use nLite to repackage**
   - Point nLite to `E:\Output`
   - Create a bootable ISO

### Command-Line Options

```
wininst_patcher.exe [-v|--verbose] [-h|--help]

-v, --verbose   Enable verbose logging output
-h, --help      Display help message and exit
```

### Interactive Prompts

#### Step 1: Input Media
- **Base ISO**: The target media to be patched (languages preserved, layout unchanged)
- **Resource ISO**: Donor media supplying translated resources

Both must be directories with recognized architecture subdirectories (I386, AMD64, IA64) — either extracted folders on disk or mounted CD/DVD drives.

#### Step 2: Output Folder
- Will be created if it doesn't exist
- If non-empty, you'll be asked to confirm overwrite
- Contains the patched media tree (ready for nLite)

#### Step 3: Language Detection & Mode
The tool auto-detects language IDs from `hivedef.inf` (INTL_LOCALE). Resources are **always** applied in Replace fashion (the old Attach mode has been retired): extracted `.bin` files are renamed to overwrite the Base language, and the language ID is updated in `intl.inf`, `hivesys.inf`, `hivedef.inf`.

Choose a processing mode (prompt `Mode [S/F]`):
- **Safe (S)**: Boot-critical files are left untouched — `ntoskrnl.exe`, `ntkr*.dll`, and `hal*.dll` pass through unchanged (no resource replacement, no checksum re-stamp), and `driver.cab` / `SP*.CAB` are not processed. The original archives are kept on the output media.
- **Full (F)**: Everything is processed like usual — every PE binary gets its resources replaced, PE checksums are re-stamped, and `Driver.cab` / `SP*.CAB` are rebuilt.

If language detection fails for either ISO, replacements still happen but the extracted `.bin` files cannot be renamed to the Base language.

---

## Output

After completion, the output directory contains:
```
Output/
  I386/             Architecture-specific binaries
    setup*.exe      Decompressed setup files
    txtsetup.sif    Setup configuration
    system32/       System files (ntdll.dll, smss.exe, etc.)
    driver.cab      Reconstructed driver cabinet
  system32/         Root-level system files
  boot/             Boot files (ntldr, boot.ini, etc.)
  [other files]     Original ISO files (copied as-is)
```

This tree is ready for import into **nLite** or other ISO repackaging tools.

---

## How It Works (Technical Overview)

### Pipeline Stages

**Step 1: Architecture & Media Detection**
- Scans for I386, AMD64, or IA64 directories
- Detects Windows version (2000, XP, 2003) from marker files
- Checks for service pack CAB files (SP1.CAB–SP4.CAB)

**Step 2: Output Configuration**
- Validates output folder (creates if needed)
- Detects language IDs from both ISOs

**Step 3: Staging Tree**
- Creates temporary working directories under `<exe_dir>\_work`
- Separates base ISO and resource ISO bins into subdirectories

**Step 4: Binary Extraction**
- Expands compressed files (.dl_, .ex_, .cp_, .sy_, .oc_) to real extensions
- Separates by type:
  - `comp_bins`: Compressed PE files (will be re-compressed later)
  - `uncomp_bins`: Already-uncompressed binaries
  - `driver_bins`: Extracted from Driver.cab (skipped in Safe mode)
  - `servicepack_bins`: Extracted from SP*.CAB (if present; skipped in Safe mode)
  - `wow_bins`: WOW64 binaries (on 64-bit media only)

**Step 5: Resource Extraction**
- Scans donor ISO binaries for embedded resources
- Extracts .RES, .MUI, and localized binary content
- Groups by target filename and language ID

**Step 6: Resource Replacement**
- Patches each base ISO binary with donor resources
- Merges string tables, dialogs, menus, accelerators
- Always runs in Replace fashion: language-specific files (.bin) are renamed to overwrite the base language
- In Safe mode, `ntoskrnl.exe`, `ntkr*.dll`, and `hal*.dll` are copied through untouched; `driver_bins` and `servicepack_bins` are not processed

**Step 7: Hex Patching (OS-specific)**
- Applies hand-coded binary patches to `setupapi.dll`, `syssetup.dll`, `sfc_os.dll`
- Patterns vary by OS version (Win2000, WinXP, Win2003, Win2003x64)
- IA64, DEC Alpha (ALPHA), and Alpha AXP 64-bit (AXP64): Requires manual pre-patched binaries (EPIC/RISC instruction sets are not amenable to automated patching)
- ALPHA / AXP64 media is treated strictly as Windows 2000 (no XP/Server 2003 exists for it), including the Win2000 KERNEL32/DSSBASE/RSABASE handling — the hex-patching step alone stays manual like IA64
- ALPHA / AXP64 support is **work in progress** and may not work fully; treat these architectures as experimental.

**Step 8: PE Checksum Re-stamping**
- Walks entire output tree recursively
- Recalculates and updates PE header checksums
- Ensures binaries pass Windows setup signature checks
- In Safe mode, the excluded kernel/HAL files are not re-stamped

**Step 9: Re-compression**
- Compressed files (`.comp_bins`) re-packed into output architecture directory
- Uncompressed files copied as-is
- Driver.cab and SP*.CAB rebuilt (in Safe mode the original archives are kept)

**Step 10: Media Assembly**
- Copies all remaining files from base ISO (boot, config, docs)
- Overlays patched binaries
- Preserves directory structure

**Post-Step 10: Fixups**
- When Base/Resource came from mounted CD/DVD media, clears the read-only attribute on the whole output tree (needed so INF edits can succeed)
- Copies unpatched critical system files (KERNEL32.DLL, PIDGEN.DLL, rsaenh.DLL, dssenh.DLL)
- Updates locale settings in INF files (intl.inf, hivesys.inf, hivedef.inf)
- Merges complex-script language files (Chinese, Japanese, Korean)
- For CJK targets: merges the **donor** `txtsetup.sif` data into the output —
  - All donor `[WinntDirectories]` sections are combined and appended to the output (duplicate keys are detected and skipped)
  - The correct donor `[SourceDisksFiles]` block (the one declaring the `c_10003.nls` codepage table) is appended to the output
  - Files from `donor\<donor_arch>` are copied into `output\<base_arch>` **without overwriting** existing files
  - The `[WinntDirectories]`/`[SourceDisksFiles]` placeholders inside the `txtsetup_1028/1041/1042/2052.txt` fixup files are ignored (they are only templates)
- Copies Help/HTML documentation from donor ISO
- Updates txtsetup.sif with new language metadata

---

## Known Limitations & Workarounds

### Q: Do Chinese/Japanese/Korean targets have special requirements?

**A:** CJK targets (Chinese Simplified `2052`, Chinese Traditional `1028`, Korean `1042`, Japanese `1041`) need additional donor media data that Western base ISOs lack. The tool now handles this automatically in **Post-Step 10**:
- The donor `txtsetup.sif` `[WinntDirectories]` sections are combined into the output — correct for translations like English Base → Korean Donor.
- The correct donor `[SourceDisksFiles]` block (containing the `c_10003.nls` codepage entry) is merged into the output so text-mode setup finds all the language-specific install files.
- Missing donor files are layered into the output arch folder (`donor\<donor_arch>` → `output\<base_arch>`) without overwriting existing files.
- The `txtsetup_<LCID>.txt` fixup files only supply placeholder section templates; their `[WinntDirectories]`/`[SourceDisksFiles]` content is deliberately skipped (the real data comes from the donor ISO).

Korean translations have been verified to work end-to-end with this merge. Ensure the donor ISO is the matching CJK language and that the donor architecture directory exists.

> **Note:** `winnt32bbu.dll` (the setup billboard) can be buggy for these languages — it may display garbled or untranslated text. This is a known cosmetic issue with the billboard during WinNT32 setup, unrelated to the txtsetup.sif merge.

### Q: Chinese characters are corrupted during text-mode setup.

**A:** You must copy `spddlang.sys` from your donor ISO. This file contains language-specific font metadata.
- Match architectures strictly (x86↔x86, x64↔x64, IA64↔IA64)
- Match build numbers if possible (or use closest available Chinese variant)

### Q: Why does the output generate half-translated ISOs?

**A:** Some PE files fail resource replacement, often due to:
- Unsupported resource section formats
- File corruption or variant layouts
- Missing or incompatible donor resources

**Workaround:** Use Resource Hacker to manually patch remaining files post-patching.

### Q: Can I translate Longhorn (Vista/2003 R2) ISOs?

**A:** Theoretically yes, if not using the .WIM format. However, this is untested and Longhorn's resource layout differs significantly. Expect issues.

### Q: Can I translate Windows 2000 ISOs?

**A:** Yes, but support is limited. Windows 2000 media layout and setup sequences differ from XP/2003. KERNEL32.DLL and RSABASE.DLL handling require special care (they ship unpatched).

### Q: What's the recommended setup for Windows XP Professional x64 Edition?

**A:**
```
Base = English Windows XP Professional x64 Edition
Donor = Any language Windows Server 2003 x86 + Any language Windows XP SP2 binaries (without overwrite)
```

This mix works because x64 Edition shares core binaries with Server 2003 but WOW64 compatibility layer (32-bit support) comes from XP SP2.

### Q: How do I patch DEC Alpha (ALPHA) or Alpha AXP 64-bit (AXP64) media?

**A:** **Warning: ALPHA / AXP64 support is work in progress and may not work fully.** These architectures are treated strictly as Windows 2000 (no XP/Server 2003 releases exist for them), receiving the Windows 2000 x86-like handling (Win2000 hex-patch baseline, unpatched KERNEL32/DSSBASE/RSABASE restoration). The hex-patching step itself works like IA64:
1. Obtain pre-patched `setupapi.dll` and `syssetup.dll` for your Alpha/AXP build
2. Place them in the tool's input directory
3. When prompted, copy them to the indicated staging folder
4. The tool will validate the architecture and re-stamp checksums

### Q: Manual action required for IA64 deployments?

**A:** Yes. The EPIC instruction set (IA64) makes automated hex patching infeasible. You must:
1. Obtain pre-patched `setupapi.dll` and `syssetup.dll` for IA64 (from a working IA64 Windows 2003 installation)
2. Place them in the tool's input directory
3. When prompted, copy them to the indicated staging folder
4. The tool will validate the architecture and re-stamp checksums

---

## Troubleshooting

### Build Fails
- **Error**: `vcvarsall.bat not found` or `VCINSTALLDIR` not set
  - **Solution**: Run from "x86 Native Tools Command Prompt for VS" or "x64 Native Tools Command Prompt for VS" (not cmd.exe)
- **Error**: Linker errors about missing `.lib` files
  - **Solution**: Ensure Visual Studio C++ toolchain is installed (not just .NET tools)

### Runtime Crashes
- Check the logfile (printed at startup, typically `wininst_patcher_<timestamp>.log`)
- Common causes:
  - Insufficient disk space (< 2 GB free)
  - Base ISO does not have recognized architecture subdirectory (I386, AMD64, IA64)
  - Permission issues (run as Administrator)
  - Corrupted or non-standard ISO layout

### Output Media Won't Boot
- Verify nLite was pointed to the correct output directory
- Ensure base ISO had valid boot files (ntldr, boot.ini on x86; efi directory on IA64)
- Check that output media was repackaged with correct ISO 9660 settings

### Language Not Applied
- Verify language detection worked (check logfile for detected LANGID)
- Resources are always applied in Replace fashion (Attach mode was retired)
- If you chose **Safe mode**, boot-critical files (`ntoskrnl.exe`, `ntkr*.dll`, `hal*.dll`) are intentionally left unpatched — re-run with **Full mode** to process them
- Verify both ISOs had the same OS version (WinXP + WinXP, not WinXP + Win2003)
- Ensure donor ISO was a complete, valid installation media (not a partial update)

---

## License

Apache License 2.0 — See LICENSE file for details.

---

## Contributing

Bug reports and pull requests are welcome. Please include:
- ISO versions tested (Windows 2000 SP4, XP SP3, Server 2003 SP2, etc.)
- Languages involved
- Logfile output if applicable
- Steps to reproduce

---

## References

- Windows PE File Format: [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- Cabinet (CAB) Format: [MS-CAB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cab/)
- nLite Project: http://www.nliteos.com/

---

## FAQ (Quick Reference)

| Q | A |
|---|---|
| **Can I use CD instead of DVD?** | Yes; media type doesn't matter. Both media may be mounted CD/DVD drives used directly, or extracted folders on disk. |
| **How long does patching take?** | Typically 15–20 minutes on a modern SSD, longer on HDDs. |
| **Can I patch multiple languages at once?** | No; run the tool separately for each language pair. |
| **Do CJK targets (Chinese/Japanese/Korean) need anything extra?** | Yes — use the matching CJK language as the Resource/donor ISO. The tool merges the donor's `txtsetup.sif` sections (`[WinntDirectories]`, `[SourceDisksFiles]`) and copies missing donor files in Post-Step 10. |
| **Will this work on Windows 7+ ISOs?** | No. This tool targets Windows 2000, XP, and Server 2003 (NT 5.x) only. |
| **Do I need nLite?** | Yes, to repackage the output into a bootable ISO. |
| **Can I use the output directly without nLite?** | Only if you manually construct the ISO with correct boot sectors and file layout. |
