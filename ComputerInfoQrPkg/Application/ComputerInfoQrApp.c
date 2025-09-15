#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include "QrCode.h"

#define QUIET_ZONE_SIZE             2
#define VENDOR_MAX_LENGTH           5
#define INFO_BUFFER_LENGTH          64

STATIC
VOID
PrepareVendorString(
  OUT CHAR8       *Buffer,
  IN  UINTN        BufferSize,
  IN  CONST CHAR16 *Vendor
  )
{
  if (BufferSize == 0) {
    return;
  }

  if (Vendor == NULL) {
    AsciiStrCpyS(Buffer, BufferSize, "UNK");
    return;
  }

  RETURN_STATUS ConversionStatus = UnicodeStrToAsciiStrS(Vendor, Buffer, BufferSize);
  if (RETURN_ERROR(ConversionStatus)) {
    AsciiStrnCpyS(Buffer, BufferSize, "UNK", BufferSize - 1);
  }

  for (UINTN Index = 0; Buffer[Index] != '\0'; Index++) {
    if (Buffer[Index] == ' ') {
      Buffer[Index] = '_';
    }
  }
}

STATIC
EFI_STATUS
GetMemoryStatistics(
  OUT UINT64 *TotalMemoryMb,
  OUT UINTN  *DescriptorCount
  )
{
  if (TotalMemoryMb == NULL || DescriptorCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EFI_STATUS            Status;
  EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
  UINTN                 MapSize = 0;
  UINTN                 MapKey;
  UINTN                 DescriptorSize = 0;
  UINT32                DescriptorVersion;

  Status = gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  MapSize += DescriptorSize * 4;
  MemoryMap = AllocateZeroPool(MapSize);
  if (MemoryMap == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->GetMemoryMap(&MapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR(Status)) {
    FreePool(MemoryMap);
    return Status;
  }

  UINT64 TotalPages = 0;
  UINTN  Count = MapSize / DescriptorSize;
  EFI_MEMORY_DESCRIPTOR *Descriptor = MemoryMap;
  for (UINTN Index = 0; Index < Count; Index++) {
    TotalPages += Descriptor->NumberOfPages;
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Descriptor + DescriptorSize);
  }

  FreePool(MemoryMap);

  *TotalMemoryMb = DivU64x32(TotalPages, 256);
  *DescriptorCount = Count;

  return EFI_SUCCESS;
}

STATIC
VOID
RenderQuietRow(
  IN UINTN TotalModules
  )
{
  UINTN Characters = TotalModules * 2;
  CHAR16 RowBuffer[(COMPUTER_INFO_QR_SIZE + (QUIET_ZONE_SIZE * 2)) * 2 + 1];

  for (UINTN Index = 0; Index < Characters; Index++) {
    RowBuffer[Index] = L' ';
  }
  RowBuffer[Characters] = L'\0';
  Print(L"%s\n", RowBuffer);
}

STATIC
VOID
RenderQrRow(
  IN CONST COMPUTER_INFO_QR_CODE *QrCode,
  IN UINTN                        RowIndex
  )
{
  CHAR16 RowBuffer[(COMPUTER_INFO_QR_SIZE + (QUIET_ZONE_SIZE * 2)) * 2 + 1];
  UINTN Position = 0;

  for (UINTN Index = 0; Index < QUIET_ZONE_SIZE; Index++) {
    RowBuffer[Position++] = L' ';
    RowBuffer[Position++] = L' ';
  }

  for (UINTN Column = 0; Column < QrCode->Size; Column++) {
    if (QrCode->Modules[RowIndex][Column] != 0) {
      RowBuffer[Position++] = L'\u2588';
      RowBuffer[Position++] = L'\u2588';
    } else {
      RowBuffer[Position++] = L' ';
      RowBuffer[Position++] = L' ';
    }
  }

  for (UINTN Index = 0; Index < QUIET_ZONE_SIZE; Index++) {
    RowBuffer[Position++] = L' ';
    RowBuffer[Position++] = L' ';
  }

  RowBuffer[Position] = L'\0';
  Print(L"%s\n", RowBuffer);
}

STATIC
VOID
RenderQrCode(
  IN CONST COMPUTER_INFO_QR_CODE *QrCode
  )
{
  UINTN DisplayWidth = QrCode->Size + (QUIET_ZONE_SIZE * 2);

  for (UINTN Index = 0; Index < QUIET_ZONE_SIZE; Index++) {
    RenderQuietRow(DisplayWidth);
  }

  for (UINTN Row = 0; Row < QrCode->Size; Row++) {
    RenderQrRow(QrCode, Row);
  }

  for (UINTN Index = 0; Index < QUIET_ZONE_SIZE; Index++) {
    RenderQuietRow(DisplayWidth);
  }
}

EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;
  CHAR8     Vendor[VENDOR_MAX_LENGTH + 1];
  CHAR8     InfoBuffer[INFO_BUFFER_LENGTH];
  UINT64    TotalMemoryMb;
  UINTN     DescriptorCount;

  SetMem(Vendor, sizeof(Vendor), 0);
  PrepareVendorString(Vendor, sizeof(Vendor), gST->FirmwareVendor);

  Status = GetMemoryStatistics(&TotalMemoryMb, &DescriptorCount);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to retrieve memory information: %r\n", Status);
    return Status;
  }

  if (TotalMemoryMb > 99999) {
    TotalMemoryMb = 99999;
  }

  if (DescriptorCount > 999) {
    DescriptorCount = 999;
  }

  AsciiSPrint(
    InfoBuffer,
    sizeof(InfoBuffer),
    "V:%a|R:%08X|M:%05Lu|D:%03u",
    Vendor,
    gST->FirmwareRevision,
    TotalMemoryMb,
    (UINT32)DescriptorCount
    );

  InfoBuffer[COMPUTER_INFO_QR_MAX_DATA_LENGTH] = '\0';
  UINTN DataLength = AsciiStrLen(InfoBuffer);
  if (DataLength > COMPUTER_INFO_QR_MAX_DATA_LENGTH) {
    DataLength = COMPUTER_INFO_QR_MAX_DATA_LENGTH;
  }

  COMPUTER_INFO_QR_CODE QrCode;
  Status = GenerateComputerInfoQrCode((CONST UINT8 *)InfoBuffer, DataLength, &QrCode);
  if (EFI_ERROR(Status)) {
    Print(L"QR code generation failed: %r\n", Status);
    return Status;
  }

  if (gST->ConOut != NULL) {
    gST->ConOut->ClearScreen(gST->ConOut);
  }

  Print(L"Computer information encoded as QR code:\n\n");
  RenderQrCode(&QrCode);
  Print(L"\nRaw data: %a\n", InfoBuffer);

  return EFI_SUCCESS;
}
