#include <Uefi.h>

#include <IndustryStandard/SmBios.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/SimpleNetwork.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/Smbios.h>

#include "QrCode.h"

#define QUIET_ZONE_SIZE                 2
#define INFO_BUFFER_LENGTH              (COMPUTER_INFO_QR_MAX_DATA_LENGTH + 1)
#define UUID_STRING_LENGTH              36
#define UUID_STRING_BUFFER_LENGTH       (UUID_STRING_LENGTH + 1)
#define MAC_ADDRESS_MAX_BYTES           32
#define MAC_STRING_MAX_LENGTH           (MAC_ADDRESS_MAX_BYTES * 2)
#define MAC_STRING_BUFFER_LENGTH        (MAC_STRING_MAX_LENGTH + 1)
#define SERIAL_NUMBER_BUFFER_LENGTH     (COMPUTER_INFO_QR_MAX_DATA_LENGTH + 1)
#define UNKNOWN_STRING                  "UNKNOWN"

STATIC
BOOLEAN
IsAsciiSpaceCharacter(
  IN CHAR8 Character
  )
{
  switch (Character) {
    case ' ':
    case '\t':
    case '\n':
    case '\r':
    case '\f':
    case '\v':
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
VOID
TrimAndSanitizeSerialNumber(
  IN OUT CHAR8 *Serial
  )
{
  if (Serial == NULL) {
    return;
  }

  CHAR8 *Start = Serial;
  while ((*Start != '\0') && IsAsciiSpaceCharacter(*Start)) {
    Start++;
  }

  CHAR8 *End = Start + AsciiStrLen(Start);
  while ((End > Start) && IsAsciiSpaceCharacter(*(End - 1))) {
    End--;
  }

  UINTN Length = (UINTN)(End - Start);
  if (Length == 0) {
    Serial[0] = '\0';
  } else {
    if (Start != Serial) {
      CopyMem(Serial, Start, Length);
    }
    Serial[Length] = '\0';
  }

  for (UINTN Index = 0; Serial[Index] != '\0'; Index++) {
    if (Serial[Index] == '|') {
      Serial[Index] = '_';
    } else if ((Serial[Index] < ' ') || (Serial[Index] > '~')) {
      Serial[Index] = '_';
    }
  }
}

STATIC
VOID
CopySmbiosString(
  OUT CHAR8                     *Destination,
  IN  UINTN                      DestinationSize,
  IN  CONST SMBIOS_STRUCTURE    *Header,
  IN  UINTN                      StringNumber
  )
{
  if (DestinationSize == 0) {
    return;
  }

  Destination[0] = '\0';

  if ((Header == NULL) || (StringNumber == 0)) {
    return;
  }

  CONST CHAR8 *Current = (CONST CHAR8 *)Header + Header->Length;
  UINTN        Index   = 1;

  while ((Index < StringNumber) && (*Current != '\0')) {
    UINTN Length = AsciiStrLen(Current);
    Current      += Length + 1;
    Index++;
  }

  if ((Index != StringNumber) || (*Current == '\0')) {
    return;
  }

  AsciiStrnCpyS(Destination, DestinationSize, Current, DestinationSize - 1);
}

STATIC
BOOLEAN
IsValidUuid(
  IN CONST EFI_GUID *Guid
  )
{
  if (Guid == NULL) {
    return FALSE;
  }

  CONST UINT8 *Bytes    = (CONST UINT8 *)Guid;
  BOOLEAN      AllZero  = TRUE;
  BOOLEAN      AllOnes  = TRUE;

  for (UINTN Index = 0; Index < sizeof(EFI_GUID); Index++) {
    if (Bytes[Index] != 0x00) {
      AllZero = FALSE;
    }
    if (Bytes[Index] != 0xFF) {
      AllOnes = FALSE;
    }
  }

  return !(AllZero || AllOnes);
}

STATIC
VOID
GetSystemUuidAndSerial(
  OUT EFI_GUID *SystemUuid,
  OUT CHAR8    *SerialNumber,
  IN  UINTN     SerialBufferLength
  )
{
  if (SystemUuid != NULL) {
    ZeroMem(SystemUuid, sizeof(EFI_GUID));
  }

  if ((SerialNumber != NULL) && (SerialBufferLength > 0)) {
    SerialNumber[0] = '\0';
  }

  EFI_SMBIOS_PROTOCOL *Smbios;
  EFI_STATUS           Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (EFI_ERROR(Status)) {
    return;
  }

  EFI_SMBIOS_HANDLE       Handle = SMBIOS_HANDLE_PI_RESERVED;
  EFI_SMBIOS_TYPE         Type;
  EFI_SMBIOS_TABLE_HEADER *Record;

  while (TRUE) {
    Status = Smbios->GetNext(Smbios, &Handle, &Type, &Record, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }

    if (Type == SMBIOS_TYPE_SYSTEM_INFORMATION) {
      SMBIOS_TABLE_TYPE1 *Type1 = (SMBIOS_TABLE_TYPE1 *)Record;
      if (SystemUuid != NULL) {
        CopyMem(SystemUuid, &Type1->Uuid, sizeof(EFI_GUID));
      }

      if ((SerialNumber != NULL) && (SerialBufferLength > 0)) {
        CopySmbiosString(SerialNumber, SerialBufferLength, (SMBIOS_STRUCTURE *)Record, Type1->SerialNumber);
      }
      break;
    }
  }
}

STATIC
VOID
GetPrimaryMacAddress(
  OUT EFI_MAC_ADDRESS *MacAddress,
  OUT UINTN           *AddressSize
  )
{
  if (MacAddress != NULL) {
    ZeroMem(MacAddress, sizeof(EFI_MAC_ADDRESS));
  }

  if (AddressSize != NULL) {
    *AddressSize = 0;
  }

  if ((MacAddress == NULL) || (AddressSize == NULL)) {
    return;
  }

  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;

  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleNetworkProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR(Status) || (HandleCount == 0) || (HandleBuffer == NULL)) {
    return;
  }

  BOOLEAN Found = FALSE;

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    EFI_SIMPLE_NETWORK_PROTOCOL *Snp = NULL;
    Status = gBS->HandleProtocol(HandleBuffer[Index], &gEfiSimpleNetworkProtocolGuid, (VOID **)&Snp);
    if (EFI_ERROR(Status) || (Snp == NULL) || (Snp->Mode == NULL)) {
      continue;
    }

    UINTN HwAddressSize = Snp->Mode->HwAddressSize;
    if ((HwAddressSize == 0) || (HwAddressSize > MAC_ADDRESS_MAX_BYTES)) {
      continue;
    }

    CopyMem(MacAddress, &Snp->Mode->PermanentAddress, sizeof(EFI_MAC_ADDRESS));
    *AddressSize = HwAddressSize;

    BOOLEAN NonZero = FALSE;
    for (UINTN ByteIndex = 0; ByteIndex < HwAddressSize; ByteIndex++) {
      if (MacAddress->Addr[ByteIndex] != 0x00) {
        NonZero = TRUE;
        break;
      }
    }

    if (!NonZero) {
      CopyMem(MacAddress, &Snp->Mode->CurrentAddress, sizeof(EFI_MAC_ADDRESS));
      for (UINTN ByteIndex = 0; ByteIndex < HwAddressSize; ByteIndex++) {
        if (MacAddress->Addr[ByteIndex] != 0x00) {
          NonZero = TRUE;
          break;
        }
      }
    }

    if (NonZero) {
      Found = TRUE;
      break;
    }

    *AddressSize = 0;
  }

  if (!Found) {
    ZeroMem(MacAddress, sizeof(EFI_MAC_ADDRESS));
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }
}

STATIC
VOID
GuidToString(
  IN  CONST EFI_GUID *Guid,
  OUT CHAR8          *Buffer,
  IN  UINTN           BufferSize
  )
{
  if ((Buffer == NULL) || (BufferSize == 0)) {
    return;
  }

  Buffer[0] = '\0';

  if (Guid == NULL) {
    return;
  }

  if (BufferSize < UUID_STRING_BUFFER_LENGTH) {
    return;
  }

  AsciiSPrint(
    Buffer,
    BufferSize,
    "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
    Guid->Data1,
    Guid->Data2,
    Guid->Data3,
    Guid->Data4[0],
    Guid->Data4[1],
    Guid->Data4[2],
    Guid->Data4[3],
    Guid->Data4[4],
    Guid->Data4[5],
    Guid->Data4[6],
    Guid->Data4[7]
    );
}

STATIC
VOID
MacAddressToString(
  IN  CONST EFI_MAC_ADDRESS *MacAddress,
  IN  UINTN                  AddressSize,
  OUT CHAR8                 *Buffer,
  IN  UINTN                  BufferSize
  )
{
  if ((Buffer == NULL) || (BufferSize == 0)) {
    return;
  }

  Buffer[0] = '\0';

  if ((MacAddress == NULL) || (AddressSize == 0)) {
    return;
  }

  if (BufferSize < (AddressSize * 2 + 1)) {
    return;
  }

  UINTN Offset = 0;
  for (UINTN Index = 0; Index < AddressSize; Index++) {
    AsciiSPrint(Buffer + Offset, BufferSize - Offset, "%02X", MacAddress->Addr[Index]);
    Offset += 2;
  }
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
  UINTN  Position = 0;

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
  IN CONST COMPUTER_INFO_QR_CODE *QrCode
  )
{
  if (gST->ConOut != NULL) {
    gST->ConOut->ClearScreen(gST->ConOut);
  }

  RenderQrCode(QrCode);
}

EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_GUID        SystemUuid;
  CHAR8           SerialNumber[SERIAL_NUMBER_BUFFER_LENGTH];
  EFI_MAC_ADDRESS MacAddress;
  UINTN           MacAddressSize;

  GetSystemUuidAndSerial(&SystemUuid, SerialNumber, sizeof(SerialNumber));
  TrimAndSanitizeSerialNumber(SerialNumber);
  if (SerialNumber[0] == '\0') {
    AsciiStrCpyS(SerialNumber, sizeof(SerialNumber), UNKNOWN_STRING);
  }

  GetPrimaryMacAddress(&MacAddress, &MacAddressSize);

  CHAR8 UuidString[UUID_STRING_BUFFER_LENGTH];
  if (IsValidUuid(&SystemUuid)) {
    GuidToString(&SystemUuid, UuidString, sizeof(UuidString));
  } else {
    AsciiStrCpyS(UuidString, sizeof(UuidString), UNKNOWN_STRING);
  }

  CHAR8 MacString[MAC_STRING_BUFFER_LENGTH];
  MacAddressToString(&MacAddress, MacAddressSize, MacString, sizeof(MacString));
  if (MacString[0] == '\0') {
    AsciiStrCpyS(MacString, sizeof(MacString), UNKNOWN_STRING);
  }

  UINTN SerialLength = AsciiStrLen(SerialNumber);
  UINTN UuidLength   = AsciiStrLen(UuidString);
  UINTN MacLength    = AsciiStrLen(MacString);
  if ((UuidLength + 1 + MacLength + 1 + SerialLength) > COMPUTER_INFO_QR_MAX_DATA_LENGTH) {
    Print(L"Encoded data is too large for the selected QR code size.\n");
    return EFI_BAD_BUFFER_SIZE;
  }

  CHAR8 InfoBuffer[INFO_BUFFER_LENGTH];
  AsciiSPrint(InfoBuffer, sizeof(InfoBuffer), "%a|%a|%a", UuidString, MacString, SerialNumber);
  UINTN DataLength = AsciiStrLen(InfoBuffer);
  if ((DataLength == 0) || (DataLength > COMPUTER_INFO_QR_MAX_DATA_LENGTH)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  COMPUTER_INFO_QR_CODE QrCode;
  EFI_STATUS            Status = GenerateComputerInfoQrCode((CONST UINT8 *)InfoBuffer, DataLength, &QrCode);
  if (EFI_ERROR(Status)) {
    Print(L"QR code generation failed: %r\n", Status);
    return Status;
  }

  ShowQrScreen(&QrCode);
  WaitForKeyPress(NULL);

  return EFI_SUCCESS;
}
