# UEFI-Playground

This repository contains a standalone EDK II package named `ComputerInfoQrPkg`.
The package builds a UEFI application that collects key firmware and memory
statistics from the running machine and renders them as a QR code directly in
the UEFI console. The QR code generator is implemented from scratch and does
not rely on any external libraries.

## Package layout

```
ComputerInfoQrPkg/
├── Application/
│   ├── ComputerInfoQrApp.c      # UEFI entry point and rendering helpers
│   ├── ComputerInfoQrApp.inf    # Module description
│   ├── QrCode.c                 # QR code encoder implementation
│   └── QrCode.h                 # Shared QR definitions
├── ComputerInfoQrPkg.dec        # Package declaration
└── ComputerInfoQrPkg.dsc        # Platform description for building
```

## Building the application

1. Set up an [EDK II](https://github.com/tianocore/edk2) workspace and install
   the toolchain for your target architecture.
2. Copy or clone this repository inside the workspace root so that
   `ComputerInfoQrPkg` sits alongside the other packages.
3. Initialize the EDK II build environment (for example, on Linux:
   `source edksetup.sh`).
4. Build the application by invoking:

   ```bash
   build -p ComputerInfoQrPkg/ComputerInfoQrPkg.dsc -m ComputerInfoQrPkg/Application/ComputerInfoQrApp.inf -a X64 -t GCC5
   ```

   Adjust `-a` and `-t` to match your desired architecture and toolchain.

The resulting EFI binary will be placed in the `Build/ComputerInfoQr/` output
folder created by EDK II. Copy the application to your preferred boot medium
(e.g. a USB drive) and launch it from a UEFI shell to view the QR code.

## Displayed information

The QR payload encodes a concise string containing:

- A truncated firmware vendor identifier.
- The firmware revision.
- The total amount of system memory (in MiB, capped to five digits).
- The number of descriptors reported in the firmware memory map (capped to
  three digits).

An ASCII rendering of the QR code is shown on screen together with the raw data
string, making it simple to scan the code with another device.
