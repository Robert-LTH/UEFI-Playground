#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/SimpleTextIn.h>

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

STATIC
EFI_STATUS
WaitForKeyPress(
  OUT EFI_INPUT_KEY *Key OPTIONAL
  )
{
  if ((gST == NULL) || (gST->ConIn == NULL)) {
    return EFI_UNSUPPORTED;
  }

  EFI_STATUS    Status;
  UINTN         EventIndex;
  EFI_INPUT_KEY LocalKey;

  while (TRUE) {
    Status = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
    if (EFI_ERROR(Status)) {
      return Status;
    }

    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &LocalKey);
    if (!EFI_ERROR(Status)) {
      if (Key != NULL) {
        *Key = LocalKey;
      }

      return EFI_SUCCESS;
    }

    if (Status != EFI_NOT_READY) {
      return Status;
    }
  }
}

STATIC
VOID
ShowQrScreen(
  IN CONST COMPUTER_INFO_QR_CODE *QrCode,
  IN CONST CHAR8                 *InfoBuffer
  )
{
  if (gST->ConOut != NULL) {
    gST->ConOut->ClearScreen(gST->ConOut);
  }

  Print(L"Computer information encoded as QR code:\n\n");
  RenderQrCode(QrCode);
  Print(L"\nRaw data: %a\n", InfoBuffer);
}

STATIC
EFI_STATUS
ShowMenu(
  IN CONST COMPUTER_INFO_QR_CODE *QrCode,
  IN CONST CHAR8                 *InfoBuffer
  )
{
  if ((gST == NULL) || (gST->ConOut == NULL)) {
    return EFI_UNSUPPORTED;
  }

  EFI_STATUS    Status;
  EFI_INPUT_KEY Selection;

  while (TRUE) {
    gST->ConOut->ClearScreen(gST->ConOut);

    Print(L"Computer Information Menu\n\n");
    Print(L"Encoded data: %a\n\n", InfoBuffer);
    Print(L"Options:\n");
    Print(L"  [1] Display the QR code\n");
    Print(L"  [Q] Quit\n\n");
    Print(L"Select an option: ");

    Status = WaitForKeyPress(&Selection);
    if (EFI_ERROR(Status)) {
      Print(L"\nFailed to read input: %r\n", Status);
      return Status;
    }

    Print(L"\n");

    if (Selection.UnicodeChar == L'1') {
      ShowQrScreen(QrCode, InfoBuffer);
      Print(L"\nPress any key to return to the menu...\n");
      Status = WaitForKeyPress(NULL);
      if (EFI_ERROR(Status)) {
        Print(L"Failed to read input: %r\n", Status);
        return Status;
      }

      continue;
    }

    if ((Selection.UnicodeChar == L'Q') || (Selection.UnicodeChar == L'q') || (Selection.ScanCode == SCAN_ESC)) {
      Print(L"Exiting application...\n");
      break;
    }

    Print(L"Unrecognized selection.\n");
    Print(L"Press any key to try again...\n");

    Status = WaitForKeyPress(NULL);
    if (EFI_ERROR(Status)) {
      Print(L"Failed to read input: %r\n", Status);
      return Status;
    }
  }

  return EFI_SUCCESS;
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

  ShowQrScreen(&QrCode, InfoBuffer);

  Print(L"\nPress any key to continue...\n");
  Status = WaitForKeyPress(NULL);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to read input: %r\n", Status);
    return Status;
  }

  Status = ShowMenu(&QrCode, InfoBuffer);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}
