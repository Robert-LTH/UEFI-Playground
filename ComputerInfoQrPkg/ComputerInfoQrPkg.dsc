[Defines]
  PLATFORM_NAME           = ComputerInfoQrPkg
  PLATFORM_GUID           = 9e497b77-3f2f-4d6f-bf34-a39ef79ff4da
  PLATFORM_VERSION        = 0.1
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY        = Build/ComputerInfoQr
  SUPPORTED_ARCHITECTURES = IA32 X64 AARCH64
  BUILD_TARGETS           = DEBUG RELEASE
  SKUID_IDENTIFIER        = DEFAULT

[LibraryClasses]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

[Components]
  ComputerInfoQrPkg/Application/ComputerInfoQrApp.inf
