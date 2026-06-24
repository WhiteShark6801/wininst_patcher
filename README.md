# wininst_patcher
Integrate MUI to Windows NT 5.x Setups

# How to build?

Launch **x86 Native Tools Command Prompt for VS** or **x64 Native Tools Command Prompt for VS** as Administrator.

Run build.cmd from there.

Enjoy.

# How to use?

1. Extract your Base ISO (your main ISO) and Donor ISO (the ISO includes the language for that)

2. Open the wininst_patcher.exe as Administrator. Enter root paths for both ISOs.

3. Select an output directory (if the directory doesn't exist, it is created automatically)

4. Choose either 'Append' or 'Replace' options. 'Append' option is a placeholder, will be removed later.

5. Wait 15-20 minutes until your ISO is built.

6. Use nLite to create your ISO.

7. Completed.

# FAQ

*Q1) Does it support every build + language combinations?*

**A1) Mostly. Japanese and Korean builds break during GUI-mode Setup due to signature checks failing on those languages. There must be a way to fix it. It'll stay unsupported for now.**

*Q2) Chinese characters are corrupted during text-mode Setup. Why?*

**A2) You have to copy the file spddlang.sys from your donor ISO. Make sure to match architectures (absolutely) and build numbers (if possible, otherwise use the file from closest available Chinese ISO)**

*Q3) Why does it generate half-translated ISOs?*

**A3) Some files fail to have resources replaced. These are errors which I can't fix for now. But will check through Resource Hacker.**

*Q4) Can I use this tool to translate Longhorn ISOs?*

**A4) Theoritically you can unless it uses the .WIM format. However it is untested.**

*Q5) Can I use this tool to translate Windows 2000 ISOs?*

**A5) Yes, but the support is limited for Windows 2000.**

*Q6) What is the recommended setup for Windows XP Professional x64 Edition?*

A6) This should be the preferrable format.

**Base = English Windows XP Professional x64 Edition**

**Donor = any language Windows Server 2003 x86 + any language Windows XP SP2 binaries without overwritten**

*A7) My question is not answered here.*

**Q7) You can create a new pull request to ask.**
