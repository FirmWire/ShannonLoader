## ShannonLoader

This repository is a standalone version and continuation of Grant Hernandez' [ShannonLoader](https://github.com/grant-h/ShannonBaseband/tree/master/reversing/ghidra/ShannonLoader).

It's a GHIDRA loader for Samsung's "Shannon" modem binaries. These modem binaries can be found in Samsung factory firmware images within tar files like `CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5`.
Extract this tar file into its two components, `modem.bin` and `modem_debug.bin`. Load `modem.bin` using GHIDRA after installing this extension. Modem files may be compressed using lz4 - be sure to decompress them using `lz4 -d modem.bin.lz4` before loading. Some older Cortex-R modem images (<2014) have only modem.bin.

## Baseband Support

* TOC Header parsing and sectioning
* SoC version detection
* ScatterLoading of Memory

### Cortex-R SoC (Pre-5G basebands)
* Image-agnostic MPU table extraction for an accurate memory map
* Image-agnostic boot time relocation table processing (for a more accurate static modem image)

### Cortex-A SoC (5G and above basebands)
* Experimental MMU map recovery for two different MMU Table storage formats

### Currently Not Supported Features
* Automatic discovery of task arrays in the firmware

## Building and Testing
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 21 installation (the default).
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `./dist`

To build, install, and test all at once on Linux, use the [`./workflow.sh`](./workflow.sh). For example:

```
GHIDRA_INSTALL_DIR=<Absolute path to Ghidra> ./workflow.sh <path to modem.bin> <path to existing or temporary ghidra project directory>
```

Note that your modem can deeply nested via compression or tar archives and this script will still work. You can pass a directory of modem files to try as well.

## Installation
- Start Ghidra and use the "Install Extensions" dialog (``File -> Install Extensions...``).
- Press the ``+`` button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.

## Additional Analysis Scripts

The loader also bundles analysis scripts to aid analysis after initial loading of the binary.

To use this scripts, you will need to add them via the GhidraScript Manager using one of the following approaches:
1) Locate your ghidra config directory (e.g., `~/.config/.ghidra/ghidra_12.0_PUBLIC/`) and add the `ShannonLoader/data/scripts` directory to the script manager
2) Clone this repository, and point the script directory to ShannonLoader/data/scripts

### Included Scripts
The included scripts were originally part of Grant Hernandez [ShannonBaseband](https://github.com/grant-h/ShannonBaseband/) repository and have been adjusted to work with pyGhidra. The following scripts are included:

- [ShannonTraceEntry.py](./data/scripts/ShannonTraceEntry.py): This script automatically types DBT entries (i.e., debug message strings) in the firmware. We recommend to run this script before auto analysis.
- [ShannonRename.py](./data/scripts/ShannonRename.py): This scripts renames functions based on the strings included in the DBT entries used by them. This provides a good approximation of what a function is supposed to do. However, the established names are not always correct, so be aware of false positves.

## Typical Analysis Workflow

Following the ShannonBaseband's repositories [suggestions](https://github.com/grant-h/ShannonBaseband/tree/master?tab=readme-ov-file#getting-started-with-shannon-firmware):


1. Download the firmware binary of choice. Make sure you have extracted the CP partition from official Samsung firmware and have further extracted the `modem.bin` file. Make sure to unlz4 the binary if it is compressed.
1. Install the ShannonLoader at the splash screen using *File* &raquo; *Install Extensions...*. Target the `ShannonLoader.zip` release that is in the latest release tag
1. Now start a new GHIDRA project and add a new file. Select the `modem.bin` file. You should see that this file's loader is automatically selected as "Samsung Shannon Modem Binary". If you do not see this, make sure that you have loaded the right file and installed the extension properly. Open GHIDRA debug console (bottom right on splash screen) to double check if there are any errors.
1. Import the file, let the loader finish and once again make sure there were no errors during loading.
1. Double click on the imported file to open CodeBrowser and hit no to auto-analysis for now.
1. Now run the `ShannonTraceEntry.py` python script from Script Manager under the "Shannon" category. Make sure to either place scripts into your user home directory at `~/ghidra_scripts` (Linux) or add the path to them in the manager. This script will identify all trace debugging information before analysis and avoid diassembling data.
1. Go to *Analysis* &raquo; *Auto analyze...*, and **uncheck the "Non-returning Functions - Discovered" analyzer** as this causes broken recovery of the `log_printf` function, leading to broken disassembly throughout the binary. If you do not uncheck this, you will need to restart your import from scratch.
1. Hit analyze and let GHIDRA churn away until it settles.
1. Next optionally run the auto-renamer script, `ShannonRename.py`. This will help you navigate the binary, but remember that the names are heuristically determined, so quality may vary. Functions with the same guessed name will have a numeric prefix appended.
1. Start reversing!

## Alternatives

Besides this Ghidra ShannonLoader, there is also an Alexander Pick's [ShannonModemLoader](https://github.com/alexander-pick/shannon_modem_loader) for IDA, with a similar feature set.

We are currently not aware of any other public Loaders for Shannon/Exynos-based modem firmware, but we would always be happy to hear about additional solutions!