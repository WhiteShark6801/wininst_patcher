# wininst_patcher

Integrate multilingual resources into Windows NT 5.x (Windows 2000, XP, Server 2003) installation media.

**wininst_patcher** is a tool for cross-stamping Windows installation discs with resources from a donor language pack. It extracts binaries from two ISO images (base and resource donor), patches PE files with localized strings, dialogs, and resources, re-stamps checksums to pass signature validation, and outputs a patched media tree ready for repackaging into a bootable ISO.

---

## Features

- **Multi-architecture support**: x86 (I386), x64 (AMD64), IA64 (Itanium), DEC Alpha (ALPHA), and Alpha AXP 64-bit (AXP64)
- **Language resource extraction**: Automatically extracts .RES/.MUI resources from PE files
- **PE resource patching**: Merges donor language resources into base ISO binaries
- **PE checksum re-stamping**: Recalculates and updates PE headers to pass signature checks
- **Recommended hex patching**: Hand-coded `setupapi.dll` / `syssetup.dll` patches apply the remaining setup-side changes. Not mandatory — every output also gets a generated `WINNT.SIF` with `DriverSigningPolicy=Ignore` / `NonDriverSigningPolicy=Ignore`, so driver-signing warnings do not appear during GUI-mode setup even without the hex edits
- **Automatic layout detection**: Detects Windows 2000, XP, and Server 2003 variants
- **Cross-architecture support**: Handles WOW64 (32-bit on 64-bit) binary mapping
- **Service pack integration**: Merges SP*.CAB files during patching
- **Safe mode**: Reads the boot-critical file list from the Base ISO's `txtsetup.sif` (the `findstr /r ",_[1-9] ,[1-9]_"` set) plus `ntoskrnl.exe`, deletes those files from both staging trees (`_work\ISO_1`, `_work\ISO_2`) before any patching, and keeps `driver.cab` / `SP*.CAB` untouched. `usetup.exe` and `smss.exe` are still updated in Safe mode
- **ALPHA comp_bins-only mode**: When the Base media is DEC Alpha, only the compressed binaries (`comp_bins`) are patched. Uncompressed binaries, drivers, `Driver.cab` / `SP*.CAB` and other binaries are copied through unchanged, and the Safe/Full prompt is skipped automatically
- **ALPHA VGA font expansion**: On Alpha output, every `vgaXXX.fo_` file in the output tree is also expanded to `vgaXXX.fon`
- **CJK donor-media merge**: For Chinese/Japanese/Korean targets, combines the donor `txtsetup.sif` `[WinntDirectories]`/`[SourceDisksFiles]` sections into the output and copies missing donor arch files (no overwrite)
- **CJK Base + Western donor 1033 fix**: CJK Base binaries also carry a US English (`1033`) resource that would otherwise stay behind and become the default. When the Base is CJK and the donor is Western (not `1033`), the donor resources are duplicated as `lang1033` and applied in a second in-place pass before Step 7
- **RTM Base + SP-integrated CJK donor fixes**: Renumbers donor media IDs in `txtsetup.sif`/`layout.inf` and keeps the donor's `ASMS` folder out of the output, so GUI-mode setup can complete on this combination
- **OEM font/NLS `[SourceDisksFiles]` fixup**: Every output is checked for the font and `.nls` files named by its `[nls]` section; missing `[SourceDisksFiles]` entries are added automatically, for any language and architecture
- **Post-build recovery mode** (`-p` / `--postbuild-only`): Finish an existing output folder by re-running only the finishing stages, without repeating extraction and resource replacement — useful when a run fails late and you don't want to start over
- **Honest failure reporting**: Output-folder creation is validated up front, and a run that could not write its output now fails immediately with a non-zero exit code instead of reporting success
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
wininst_patcher.exe [-v|--verbose] [-p|--postbuild-only] [-h|--help]

-v, --verbose         Enable verbose logging output
-p, --postbuild-only  Finish an existing output folder instead of patching
                      from scratch (see "Post-Build-Only Recovery Mode")
-h, --help            Display help message and exit
```

### Interactive Prompts

#### Step 1: Input Media
- **Base ISO**: The target media to be patched (languages preserved, layout unchanged)
- **Resource ISO**: Donor media supplying translated resources

Both must be directories with recognized architecture subdirectories (I386, AMD64, IA64) — either extracted folders on disk or mounted CD/DVD drives.

#### Step 2: Output Folder
- Must be a fully-qualified absolute path — `C:\Output`, `D:\Media\out`, or a UNC path `\\server\share\out`. Relative paths are rejected.
- The drive letter must be a **single letter**. A typo such as `7C:\Output` is rejected outright rather than silently failing 20 minutes later.
- Will be created if it doesn't exist. If it cannot be created, the tool aborts immediately with `[FATAL] Output folder could not be created.` before any staging work begins.
- If non-empty, you'll be asked to confirm overwrite
- Contains the patched media tree (ready for nLite)

#### Step 3: Language Detection & Mode
The tool auto-detects language IDs from `hivedef.inf` (INTL_LOCALE). Resources are **always** applied in Replace fashion (the old Attach mode has been retired): extracted `.bin` files are renamed to overwrite the Base language, and the language ID is updated in `intl.inf`, `hivesys.inf`, `hivedef.inf`.

Choose a processing mode (prompt `Mode [S/F]`):
- **Safe (S)**: Boot-critical files are left untouched. The list is read from the Base ISO's `txtsetup.sif`, mirroring `type TXTSETUP.SIF | findstr /r ",_[1-9] ,[1-9]_"` (every file text-mode setup loads from disk), plus `ntoskrnl.exe`. Those files are deleted from both staging trees (`_work\ISO_1` and `_work\ISO_2`) before extraction, so no resource replacement (and no checksum re-stamp) happens for them; Step 9 then copies the original Base files into the output. `usetup.exe` and `smss.exe` are **not** excluded: the post-step `usetup.exe` → `system32\smss.exe` copy runs in Safe mode too, so text-mode setup is translated as usual. `driver.cab` / `SP*.CAB` are not processed and the original archives are kept on the output media. All other binaries are patched normally.
- **Full (F)**: Everything is processed like usual — every PE binary gets its resources replaced, PE checksums are re-stamped, and `Driver.cab` / `SP*.CAB` are rebuilt.

> **ALPHA Base media:** the `Mode [S/F]` prompt is skipped. The run always uses
> an automatic comp_bins-only mode: only compressed binaries (`comp_bins`) are
> resource-patched and rebuilt. `uncomp_bins`, `driver_bins`,
> `servicepack_bins` and WOW bins are not processed; their Base ISO originals
> are copied through by Step 9. `Driver.cab` and any `SP*.CAB` stay untouched.
> After the output is assembled, every `vgaXXX.fo_` in the output tree is also
> expanded to `vgaXXX.fon` (the `.fo_` source is kept).

If language detection fails for either ISO, replacements still happen but the extracted `.bin` files cannot be renamed to the Base language.

---

## Post-Build-Only Recovery Mode

A full run spends most of its time on Steps 3–7 (extracting compressed binaries, pulling resources out of the donor, and rewriting every PE). If a run dies late — a broken `Driver.cab` build, a cancelled prompt, a machine reboot — you normally have to start that all over again.

`-p` / `--postbuild-only` skips straight to the finishing stages and applies them to an output folder you already have.

```batch
wininst_patcher.exe -p
```

### What runs

| Stage | Behaviour |
|---|---|
| **Step 1** — Inputs | Processed as normal. You are still asked for the Base and Resource ISO roots, because the fixups resolve against them. |
| **Step 2** — Output folder | Processed, with different rules (see below). |
| **Steps 3–10** | **Skipped.** No staging tree is created, no binaries are extracted or patched, no CABs are rebuilt. The output is assumed to already contain the patched binaries. |
| **Pre-Post-Step-10** — *new* | Base media text files are copied over the output, overwriting existing copies. |
| **Post-Step 10** — Fixups | Applied in full, as in a normal run. |

Because nothing is extracted or repacked, there is no Safe/Full mode choice — the `Mode [S/F]` prompt is not shown.

### Output folder requirements

These differ from a normal run, and are deliberately stricter:

- The folder **must already exist**. The tool will not create it — creating it would only mask a mistyped path.
- It must be **writable**. This is verified up front with a scratch-file probe, so a read-only ACL or a stale optical mount is reported immediately instead of failing one INF file at a time.
- Read-only attributes are cleared across the tree before any fixup runs, because the fixups rewrite `.inf` / `.sif` files in place and would otherwise hit `ERROR_ACCESS_DENIED`.
- It should be the output folder of the failed run — typically one that is already populated with patched binaries.

### The intermediate copy step

Immediately before the Post-Step 10 fixups, these extensions are copied from the Base ISO into the output, **overwriting** whatever is there:

```
*.inf    *.in_    *.ca_    *.cat    *.sif
```

The copy is recursive and recreates the directory layout. Files with any other extension are left alone.

This exists because a run that failed before Step 10 never copied the base media's text files into the output. Without it, the fixups would either fail to find the files they need to edit or edit stale copies, leaving a subtly broken media tree that looks finished.

### When to use it

- A run failed during Step 8 (CAB rebuild) or the post-step fixups
- You cancelled a run partway through and want the finishing stages applied
- You have manually corrected files in an existing output tree and want the fixups re-applied

### What it does *not* do

It cannot recover a run that failed during Steps 3–7, because it has no way to rebuild the patched binaries. If extraction or resource replacement never completed, use a full run.

---

## Output

After completion, the output directory contains:
```
Output/
  I386/             Architecture-specific binaries
    setup*.exe      Decompressed setup files
    txtsetup.sif    Setup configuration
    WINNT.SIF       Generated setup answer file (driver signing ignored)
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
- Checks the Base **and** the donor media independently for service pack CAB files (SP1.CAB–SP4.CAB), reporting each one separately:
  ```
  [INFO ] Service pack on Base media:     none (RTM)
  [INFO ] Service pack on Resource media: SP3
  [INFO ] Service pack processing enabled: yes
  ```
  The **Base** level is what selects the Step 7 hex-patch variants, because those patterns are matched against Base binaries. The donor level only decides whether `SP*.CAB` handling runs. A Base and donor at *different* SP levels is allowed and logs a warning; the Base level wins.

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
- In Safe mode, the boot-critical files listed in the Base `txtsetup.sif` (plus `ntoskrnl.exe`) are deleted from `_work\ISO_1` and `_work\ISO_2` before extraction, so they are never patched. `usetup.exe` and `smss.exe` are not part of this set and are updated in both modes

**Step 5: Resource Extraction**
- Scans donor ISO binaries for embedded resources
- Extracts .RES, .MUI, and localized binary content
- Groups by target filename and language ID

**Step 6: Resource Replacement**
- Patches each base ISO binary with donor resources
- Merges string tables, dialogs, menus, accelerators
- Always runs in Replace fashion: language-specific files (.bin) are renamed to overwrite the base language
- In Safe mode, the files listed in the Base `txtsetup.sif` boot set (plus `ntoskrnl.exe`) are copied through untouched; `driver_bins` and `servicepack_bins` are not processed
- **CJK Base + Western donor second pass:** CJK Base binaries usually carry two resources per item, one at `1033` (US English) and one at the CJK language. Step 6 replaces the CJK slot with the donor content, but the untouched `1033` resource would remain and become the default, so the UI would fall back to English. When the Base is a CJK language, the donor is Western (non-CJK) and not `1033`, the already-renamed donor resources are duplicated as `lang1033` and applied in a second in-place pass before Step 7. This is the *rename to 1033 + second pass* approach: it costs roughly twice the Step 6 runtime but never leaves a binary without a usable resource set
- On ALPHA Base media, only `comp_bins` is processed; `uncomp_bins`, `driver_bins`, `servicepack_bins` and WOW bins are left as shipped on the Base ISO
- Each file is named in the log *before* it is processed (`Processing: ...`), so if the run ever dies mid-file, the last line identifies the file rather than its predecessor
- With `-v`, every resource blob is logged twice - `-> <blob> (<n> bytes)` just before it is submitted and `~ <blob> (<n> bytes)` once it applied - on the screen **and** in the logfile. The last `->` line without a matching `~` is the blob that hit trouble
- Each file is updated in a short-lived **isolation child process** (`--apply-one`, an internal option). `BeginUpdateResource`/`UpdateResource` build the whole pending resource image in memory and rewrite the target PE on commit; when the Base and donor binaries are different builds, the updater can corrupt its own heap. Windows then reports `STATUS_HEAP_CORRUPTION (0xC0000374)` in `ntdll.dll` at a *later* heap operation, which no `__try`/`__except` around those three calls can catch
- A child that dies therefore cannot take down the run: the parent logs `RESOURCE UPDATE CRASHED`, restores the pristine Base copy over the output, and carries on. A file that had any faulting blob is treated the same way (`RESOURCE UPDATE FAILED`) instead of committing a half-translated binary
- Those files stay in the Base language. The run summary lists how many were affected; the `RESOURCE UPDATE FAILED`/`CRASHED` lines name them. Matching the Base and donor builds (same service pack and component set) avoids the problem entirely

**Step 7: Hex Patching (OS-specific)**
- **Optional but strongly recommended.** Hex patching is not required for a run to complete. Driver-signing enforcement is handled separately by the generated `WINNT.SIF` (see Post-Step 10); the patches here still apply the setup-side changes and are recommended for correct cross-language setup behaviour.
- Applies hand-coded binary patches to `setupapi.dll`, `syssetup.dll`, `sfc_os.dll`
- Patterns vary by OS version (Win2000, WinXP, Win2003, Win2003x64) **and** by the Base media's service-pack level (XP uses one set below SP2 and another at SP2+; Server 2003 uses one set for RTM and another for SP+)
- Every pattern is verified after matching. A pattern that finds no match is logged as a warning rather than silently skipped, so a wrong variant selection surfaces immediately:
  ```
  [WARN ]     [!] No match for 8BFF558BEC8B452C -> 33C0C230008B452C in SETUPAPI.DLL.
              The binary does not have the expected layout - check the detected
              Base OS / service-pack level.
  ```
- The former x86 `syssetup.dll` fallback (`C6 45 08 01` → `C6 45 08 00`) has been retired. Driver-signing enforcement is now disabled by the generated `WINNT.SIF` described under Post-Step 10.
- IA64, DEC Alpha (ALPHA), and Alpha AXP 64-bit (AXP64): Requires manual pre-patched binaries (EPIC/RISC instruction sets are not amenable to automated patching). The manually supplied `setupapi.dll` / `syssetup.dll` still get their resources replaced. On a CJK Base with a Western donor, both files receive the same two-pass treatment as Step 6: their resources are replaced once for the CJK slot and again for `lang1033`, so the leftover US English resource does not become the default
- ALPHA / AXP64 media is treated strictly as Windows 2000 (no XP/Server 2003 exists for it), including the Win2000 KERNEL32/DSSBASE/RSABASE handling — the hex-patching step alone stays manual like IA64
- ALPHA / AXP64 support is **work in progress** and may not work fully; treat these architectures as experimental.

**Step 8: PE Checksum Re-stamping**
- Walks entire output tree recursively
- Recalculates and updates PE header checksums
- Ensures binaries pass Windows setup signature checks
- In Safe mode, the excluded boot-critical files are not re-stamped

**Step 9: Re-compression**
- Compressed files (`.comp_bins`) re-packed into output architecture directory
- Uncompressed files copied as-is
- Driver.cab and SP*.CAB rebuilt (in Safe mode the original archives are kept)
- On ALPHA Base media only `comp_bins` is rebuilt; uncompressed binaries and archives are copied from the Base ISO unchanged

**Step 10: Media Assembly**
- Copies all remaining files from base ISO (boot, config, docs)
- Overlays patched binaries
- Preserves directory structure
- On ALPHA output, expands every `vgaXXX.fo_` to `vgaXXX.fon` (the compressed `.fo_` file is kept)

**Pre-Post-Step 10: Base Media Text Files** *(post-build-only mode only)*
- Recursively copies `*.inf`, `*.in_`, `*.ca_`, `*.cat` and `*.sif` from the Base ISO into the output, overwriting existing copies
- Recreates the directory layout; all other extensions are left untouched
- Restores files that a run failing before Step 10 never copied, so the fixups below edit current copies
- Not run in a normal full run — Step 10 has already copied the base tree by then

**Post-Step 10: Fixups**
- When Base/Resource came from mounted CD/DVD media, clears the read-only attribute on the whole output tree (needed so INF edits can succeed). In post-build-only mode this clearing is unconditional, because the output folder is user-supplied and may have come off optical media regardless of what the inputs look like
- Copies unpatched critical system files (KERNEL32.DLL, PIDGEN.DLL, rsaenh.DLL, dssenh.DLL)
- Copies `I386\USETUP.EXE` over `I386\SYSTEM32\SMSS.EXE` in every mode, including Safe mode, so text-mode setup is translated
- Updates locale settings in INF files (intl.inf, hivesys.inf, hivedef.inf)
- Merges complex-script language files (Chinese, Japanese, Korean)
- For CJK targets: merges the **donor** `txtsetup.sif` data into the output —
  - All donor `[WinntDirectories]` sections are combined and appended to the output (duplicate keys are detected and skipped)
  - The correct donor `[SourceDisksFiles]` block (the one declaring the `c_10003.nls` codepage table) is appended to the output
  - Files from `donor\<donor_arch>` are copied into `output\<base_arch>` **without overwriting** existing files
  - The `[WinntDirectories]`/`[SourceDisksFiles]` placeholders inside the `txtsetup_1028/1041/1042/2052.txt` fixup files are ignored (they are only templates)
- **(XIV)** When the Base media is **RTM** and the donor ships an **integrated service pack**, two extra corrections run — see [RTM Base + SP-Integrated Donor](#rtm-base--sp-integrated-cjk-donor)
- **(XV)** Universal `[nls]` file-entry fixup: reads `OemHalFont` and the first `.nls` table from `OemCodepage` in the output `[nls]` section and adds the canonical `[SourceDisksFiles]` lines when an entry is missing (e.g. `c_857.nls = 1,,,,,,2_,2,0,0`, `vga857.fon = 1,,,,,,3_,22,0,,,1,2`). Runs for every language and architecture, and never modifies an existing entry
- **(XVI)** Generates `<output>\<arch>\WINNT.SIF` (e.g. `I386\WINNT.SIF`, overwriting any copy from the Base media) with:
  - `[Data]` `Autopartition=0`, `MsDosInitiated=0`, `UnattendedInstall="No"`
  - `[Unattended]` `UnattendMode=ProvideDefault`, `UnattendSwitch="No"`, `OemPreinstall="Yes"`, `FileSystem=*`, `WaitForReboot="No"`, `NoWaitAfterTextMode=0`, `NoWaitAfterGUIMode=1`, `DriverSigningPolicy=Ignore`, `NonDriverSigningPolicy=Ignore`
  - `[SetupParams]` `SkipMissingFiles="Yes"`
  - The `DriverSigningPolicy` / `NonDriverSigningPolicy` entries suppress the constant driver-signing warnings during GUI-mode setup. Applied to every architecture, including in post-build-only mode
- Copies Help/HTML documentation from donor ISO
- Updates txtsetup.sif with new language metadata

---

## RTM Base + SP-Integrated CJK Donor

A CJK donor that ships with an integrated service pack describes its files with media IDs that only exist on the donor's own, larger medium. Step XIII merges those donor `[SourceDisksFiles]` lines into the output, so the output ends up pointing at disks the RTM Base media does not have — and the donor also carries an `ASMS` folder belonging to that service pack.

Both problems are corrected automatically, but **only** when all three conditions hold:

1. The Base media is **RTM** — no `SP1.CAB`–`SP4.CAB` found on it
2. The donor media **has** a service pack
3. The target language is **CJK** (Chinese Simplified `2052`, Chinese Traditional `1028`, Korean `1042`, Japanese `1041`)

If the Base media has its own service pack, none of this runs — that combination is already consistent.

### Media ID renumbering

Applied to both `txtsetup.sif` and `layout.inf` in the output. The table depends on the detected Base media generation:

| Base media | Replacements |
|---|---|
| Windows 2000 (also ALPHA / AXP64) | `2,,` → `1,,` |
| Windows XP / Server 2003 (x86) | `100,,` → `1,,` and `107,,` → `7,,` |
| Windows XP / Server 2003 AMD64 / IA64 | `155,,` → `55,,` and `156,,` → `56,,`, plus `100,,` → `1,,` and `107,,` → `7,,` |

These are literal whole-file substring replacements, so they apply everywhere the fragment occurs, not just on known lines. Every replacement is counted and logged, e.g.:

```
[XIV]  txtsetup.sif: renumbered 3 media ID fragment(s).
```

### ASMS folder exclusion

When the combination above applies and the donor has an `ASMS` folder, that folder is skipped during the (XIII) donor file copy — neither the folder nor anything under it is created in the output. Left in place, GUI-mode setup attempts to service it and fails.

The exclusion is applied to the donor tree as it is copied, so it covers `ASMS` whether it sits at the donor root or inside the donor architecture directory.

### If setup still fails

Check the log for `(XIV)` lines. If you see `no known media-ID map for this Base architecture`, the ID table needs an entry for your media — report the Base OS/architecture and the relevant `txtsetup.sif` lines.

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

### Q: What if the Base ISO is CJK but the Donor is a Western language?

**A:** The tool logs a warning and you should replace `spddlang.sys` in the output with the Western version from a Western ISO (e.g. the donor media). Because the Base is CJK, the output keeps the CJK-specific `spddlang.sys` font-metadata file, which is not appropriate for a Western target — text-mode setup may mis-render fonts or hit font-metadata inconsistencies. Copy a Western `spddlang.sys` (match architectures and build numbers if possible) over the output's version after the patch.

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

### Q: Is hex patching mandatory?

**A:** No, but it is strongly recommended. Every output gets a generated `WINNT.SIF` (`<arch>\WINNT.SIF`) with `DriverSigningPolicy=Ignore` and `NonDriverSigningPolicy=Ignore`, which suppresses driver-signing warnings during GUI-mode setup even when a hex pattern does not match. The Step 7 patches still apply the remaining setup-side changes and are recommended for correct cross-language setup behaviour.

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

**A:** **Warning: ALPHA / AXP64 support is work in progress and may not work fully.** These architectures are treated strictly as Windows 2000 (no XP/Server 2003 releases exist for them), receiving the Windows 2000 x86-like handling (Win2000 hex-patch baseline, unpatched KERNEL32/DSSBASE/RSABASE restoration). On a 32-bit ALPHA Base, the tool automatically runs in comp_bins-only mode (no Safe/Full prompt): only compressed binaries are patched, while uncompressed binaries, drivers and cabinets stay as shipped. All `vgaXXX.fo_` files in the finished output are also expanded to `vgaXXX.fon`. The hex-patching step itself works like IA64:
1. Obtain pre-patched `setupapi.dll` and `syssetup.dll` for your Alpha/AXP build
2. Place them in the tool's input directory
3. When prompted, copy them to the indicated staging folder
4. The tool will validate the architecture and re-stamp checksums
5. The tool replaces their resources with the donor language. On a CJK Base with a Western donor, it runs a second `lang1033` pass for these two files so the English resource does not remain as the default

### Q: Manual action required for IA64 deployments?

**A:** Yes. The EPIC instruction set (IA64) makes automated hex patching infeasible. You must:
1. Obtain pre-patched `setupapi.dll` and `syssetup.dll` for IA64 (from a working IA64 Windows 2003 installation)
2. Place them in the tool's input directory
3. When prompted, copy them to the indicated staging folder
4. The tool will validate the architecture and re-stamp checksums
5. The tool replaces their resources with the donor language. On a CJK Base with a Western donor, it runs a second `lang1033` pass for these two files so the English resource does not remain as the default

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

### Hex Patches Didn't Apply (no `[+] Patched ...` lines)
This almost always means the wrong binary variant was selected, not that the patch failed to apply.

- Look at Step 1 first: `Service pack on Base media:` gives the level used for pattern selection. If it reports `SP3` but you supplied RTM media, the media really does contain `SP1.CAB`–`SP4.CAB` — check the ISO you mounted.
- If the level is right but patterns still miss, the binary is an unexpected build. Compare the first bytes of `setupapi.dll`/`syssetup.dll` against the `from` column of the patch table in `Pipeline.cpp` and report the mismatch. A missed pattern is reported as a warning; the run continues, and driver-signing enforcement is still disabled by the generated `WINNT.SIF`.
- `Detected Base OS: Windows XP (SP0 / RTM)` now makes an RTM Base explicit — previously this read as `(SP0)`.

### Output Folder Rejected at Step 2
- **`not a valid absolute path`** — the path was relative (`isos\out`) or malformed. Use a fully-qualified path: `C:\Output`.
- **`"7C:\folder" is invalid`** — there is more than one character before the colon. This is the classic typo when a stray digit gets prepended to the drive letter. Retype it as `C:\folder`.
- **`[FATAL] Output folder could not be created. Aborting.`** — the path is well-formed but could not be created. Check free disk space, path length, and permissions. The tool stops here on purpose rather than running the whole pipeline against a destination that does not exist.
- With `-p`: **`not a directory`** means the output folder must already exist in this mode, and **`[FATAL] Output folder is not writable`** means it exists but cannot be written to.

### A Run Failed and I Don't Want to Start Over
Use `-p` / `--postbuild-only` to re-apply the finishing stages to the existing output folder. See [Post-Build-Only Recovery Mode](#post-build-only-recovery-mode). Note that it can only finish a run that failed at Step 8 or later — if Steps 3–7 never completed, a full run is required.

### Language Not Applied
- Verify language detection worked (check logfile for detected LANGID)
- Resources are always applied in Replace fashion (Attach mode was retired)
- If you chose **Safe mode**, the boot-critical files (the Base `txtsetup.sif` list plus `ntoskrnl.exe`) are intentionally left unpatched - re-run with **Full mode** to process them. `usetup.exe` / `smss.exe` are updated in both modes, so text-mode setup is translated either way
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
| **A run failed — do I have to start over?** | Not always. `-p` / `--postbuild-only` re-applies the finishing stages (Base text files + Post-Step 10 fixups) to your existing output folder, skipping the slow Steps 3–10. It works for failures at Step 8 or later; failures in Steps 3–7 need a full run. |
| **How long does patching take?** | Typically 15–20 minutes on a modern SSD, longer on HDDs. `-p` is near-instant by comparison. |
| **Can I patch multiple languages at once?** | No; run the tool separately for each language pair. |
| **Is hex patching mandatory?** | No. Every output gets a generated `WINNT.SIF` with driver signing set to `Ignore`; the Step 7 hex patches are recommended but not required for the run to complete. |
| **Why does the UI still show English after translating a CJK Base?** | The Base binaries carried a `1033` resource alongside the CJK one. The tool now duplicates the donor resources as `lang1033` and runs a second replacement pass, so both slots carry the donor language. |
| **Do CJK targets (Chinese/Japanese/Korean) need anything extra?** | Yes — use the matching CJK language as the Resource/donor ISO. The tool merges the donor's `txtsetup.sif` sections (`[WinntDirectories]`, `[SourceDisksFiles]`) and copies missing donor files in Post-Step 10. |
| **Will this work on Windows 7+ ISOs?** | No. This tool targets Windows 2000, XP, and Server 2003 (NT 5.x) only. |
| **Do I need nLite?** | Yes, to repackage the output into a bootable ISO. |
| **Can I use the output directly without nLite?** | Only if you manually construct the ISO with correct boot sectors and file layout. |
