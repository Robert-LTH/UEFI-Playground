#include <Uefi.h>

#include <IndustryStandard/Pci.h>
#include <IndustryStandard/SmBios.h>
#include <Guid/SmBios.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/GraphicsOutput.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Http.h>
#include <Protocol/SimpleNetwork.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/PciIo.h>
#include <Protocol/ServiceBinding.h>
#include <Protocol/Smbios.h>

#include "QrCode.h"

#ifndef PCI_HEADER_TYPE_DEVICE
#define PCI_HEADER_TYPE_DEVICE 0x00
#endif

#define QUIET_ZONE_SIZE                 2
#define JSON_PAYLOAD_BUFFER_LENGTH      (COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH + 1)
#define HARDWARE_MODEL_BUFFER_LENGTH    128
#define HARDWARE_SIZE_BUFFER_LENGTH     64
#define UUID_STRING_LENGTH              36
#define UUID_STRING_BUFFER_LENGTH       (UUID_STRING_LENGTH + 1)
#define MAC_ADDRESS_MAX_BYTES           32
#define MAC_STRING_MAX_LENGTH           (MAC_ADDRESS_MAX_BYTES * 2)
#define MAC_STRING_BUFFER_LENGTH        (MAC_STRING_MAX_LENGTH + 1)
#define SERIAL_NUMBER_BUFFER_LENGTH     (COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH + 1)
#define UNKNOWN_STRING                  "UNKNOWN"
#define DHCP_OPTION_PAD                 0
#define DHCP_OPTION_SUBNET_MASK         1
#define DHCP_OPTION_ROUTER              3
#define DHCP_OPTION_DNS_SERVERS         6
#define DHCP_OPTION_DOMAIN_NAME         15
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_IP_ADDRESS_LEASE_TIME  51
#define DHCP_OPTION_SERVER_IDENTIFIER   54
#define DHCP_OPTION_PARAMETER_REQUEST_LIST  55
#define DHCP_OPTION_RENEWAL_T1_TIME     58
#define DHCP_OPTION_REBINDING_T2_TIME   59
#define DHCP_OPTION_END                 255
#define COMPUTER_INFO_QR_SERVER_URL_OPTION  224
#define DHCP_OPTION_MAX_LENGTH              255
#define IPV4_STRING_BUFFER_LENGTH           16
#define SERVER_URL_MAX_LENGTH               512
#define HARDWARE_INVENTORY_INITIAL_CAPACITY 512
#define MAX_HARDWARE_ID_VARIANTS            9

STATIC BOOLEAN mWaitForKeyPressSupported = TRUE;

STATIC CONST UINT8 mDhcpParameterRequestOptions[] = {
  DHCP_OPTION_SUBNET_MASK,
  DHCP_OPTION_ROUTER,
  DHCP_OPTION_DNS_SERVERS,
  DHCP_OPTION_DOMAIN_NAME,
  DHCP_OPTION_BROADCAST_ADDRESS,
  DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
  DHCP_OPTION_SERVER_IDENTIFIER,
  DHCP_OPTION_RENEWAL_T1_TIME,
  DHCP_OPTION_REBINDING_T2_TIME,
  COMPUTER_INFO_QR_SERVER_URL_OPTION
};

//
// Persistent storage for the DHCP parameter request option list so the DHCP
// client can safely reference the data after this module configures it.
//
STATIC UINT8 mDhcpParameterRequestBuffer[
  sizeof(EFI_DHCP4_PACKET_OPTION) + sizeof(mDhcpParameterRequestOptions) - 1
];

STATIC EFI_DHCP4_PACKET_OPTION *mDhcpParameterRequestOptionList[1];

STATIC BOOLEAN mDhcpParameterRequestListInitialized = FALSE;

STATIC
EFI_STATUS
WaitForKeyPress(
  OUT EFI_INPUT_KEY *Key OPTIONAL
  );

STATIC
EFI_STATUS
PromptForServerUrl(
  OUT CHAR16 **ServerUrl
  );

STATIC
VOID
PauseWithPrompt(
  IN CONST CHAR16 *Prompt,
  IN CONST CHAR16 *ErrorPrefix OPTIONAL
  );

STATIC
EFI_STATUS
InitializeNicOnHandle(
  IN EFI_HANDLE Handle
  );

STATIC
EFI_STATUS
StartDhcpClientIfStopped(
  IN     EFI_DHCP4_PROTOCOL *Dhcp4,
  IN OUT EFI_DHCP4_MODE_DATA *ModeData,
  OUT    BOOLEAN            *ClientStarted OPTIONAL
  );

STATIC
EFI_STATUS
BuildHardwareInventoryPayload(
  OUT CHAR8 **JsonPayload,
  OUT UINTN *PayloadLength
  );

STATIC
EFI_STATUS
SendHttpPostRequest(
  IN EFI_HTTP_PROTOCOL *Http,
  IN CONST CHAR16      *ServerUrl,
  IN CONST CHAR8       *Payload,
  IN UINTN              PayloadLength,
  IN BOOLEAN            IncludeDhcpClientHeader,
  IN CONST CHAR16      *PayloadDescription
  );

STATIC
BOOLEAN
ShouldIncludeDhcpClientHeaderForUrl(
  IN CONST CHAR16 *ServerUrl
  );

STATIC
BOOLEAN
IsValidUuid(
  IN CONST EFI_GUID *Guid
  );

STATIC
VOID
GetCpuInfo(
  OUT CHAR8 *CpuModel,
  IN UINTN  CpuModelSize,
  OUT CHAR8 *CpuSize,
  IN UINTN  CpuSizeSize
  );

STATIC
VOID
GetBaseboardInfo(
  OUT CHAR8 *BoardModel,
  IN UINTN  BoardModelSize,
  OUT CHAR8 *BoardSize,
  IN UINTN  BoardSizeSize
  );

STATIC
VOID
GetMemoryInfo(
  OUT CHAR8 *MemoryModel,
  IN UINTN  MemoryModelSize,
  OUT CHAR8 *MemorySize,
  IN UINTN  MemorySizeSize
  );

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
VOID
NormalizeAsciiString(
  IN OUT CHAR8 *String
  )
{
  TrimAndSanitizeSerialNumber(String);
}

STATIC
CHAR8
AsciiToUpperChar(
  IN CHAR8 Character
  )
{
  if ((Character >= 'a') && (Character <= 'z')) {
    return (CHAR8)(Character - ('a' - 'A'));
  }

  return Character;
}

STATIC
BOOLEAN
AsciiStringsEqualIgnoreCase(
  IN CONST CHAR8 *First,
  IN CONST CHAR8 *Second
  )
{
  if ((First == NULL) || (Second == NULL)) {
    return FALSE;
  }

  while ((*First != '\0') && (*Second != '\0')) {
    if (AsciiToUpperChar(*First) != AsciiToUpperChar(*Second)) {
      return FALSE;
    }

    First++;
    Second++;
  }

  return ((*First == '\0') && (*Second == '\0'));
}

STATIC
BOOLEAN
IsMeaningfulSerialString(
  IN CONST CHAR8 *Serial
  )
{
  if ((Serial == NULL) || (Serial[0] == '\0')) {
    return FALSE;
  }

  if (AsciiStringsEqualIgnoreCase(Serial, "UNKNOWN") ||
      AsciiStringsEqualIgnoreCase(Serial, "NOT SPECIFIED") ||
      AsciiStringsEqualIgnoreCase(Serial, "NONE") ||
      AsciiStringsEqualIgnoreCase(Serial, "DEFAULT STRING") ||
      AsciiStringsEqualIgnoreCase(Serial, "SYSTEM SERIAL NUMBER") ||
      AsciiStringsEqualIgnoreCase(Serial, "TO BE FILLED BY O.E.M.") ||
      AsciiStringsEqualIgnoreCase(Serial, "TO BE FILLED BY OEM")) {
    return FALSE;
  }

  return TRUE;
}

STATIC
BOOLEAN
TryCopyMeaningfulSmbiosSerial(
  OUT CHAR8                  *SerialNumber,
  IN  UINTN                   SerialBufferLength,
  IN  CONST SMBIOS_STRUCTURE *Record,
  IN  UINTN                   StringNumber
  )
{
  if ((SerialNumber == NULL) || (SerialBufferLength == 0) || (Record == NULL) || (StringNumber == 0)) {
    return FALSE;
  }

  CHAR8 TempSerial[SERIAL_NUMBER_BUFFER_LENGTH];
  ZeroMem(TempSerial, sizeof(TempSerial));

  CopySmbiosString(TempSerial, sizeof(TempSerial), Record, StringNumber);
  TrimAndSanitizeSerialNumber(TempSerial);

  if (!IsMeaningfulSerialString(TempSerial)) {
    return FALSE;
  }

  AsciiStrCpyS(SerialNumber, SerialBufferLength, TempSerial);
  return TRUE;
}

STATIC
EFI_STATUS
GetSmbiosRawTable(
  OUT CONST UINT8 **TableStart,
  OUT UINTN        *TableLength
  )
{
  if ((TableStart == NULL) || (TableLength == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *TableStart  = NULL;
  *TableLength = 0;

  if ((gST == NULL) || (gST->ConfigurationTable == NULL)) {
    return EFI_NOT_READY;
  }

  for (UINTN Index = 0; Index < gST->NumberOfTableEntries; Index++) {
    EFI_CONFIGURATION_TABLE *Entry = &gST->ConfigurationTable[Index];

    if (CompareGuid(&Entry->VendorGuid, &gEfiSmbios3TableGuid)) {
      SMBIOS_TABLE_3_0_ENTRY_POINT *EntryPoint = (SMBIOS_TABLE_3_0_ENTRY_POINT *)Entry->VendorTable;
      if ((EntryPoint == NULL) || (EntryPoint->TableAddress == 0) || (EntryPoint->TableMaximumSize == 0)) {
        continue;
      }

      *TableStart  = (CONST UINT8 *)(UINTN)EntryPoint->TableAddress;
      *TableLength = (UINTN)EntryPoint->TableMaximumSize;
      return EFI_SUCCESS;
    }

    if (CompareGuid(&Entry->VendorGuid, &gEfiSmbiosTableGuid)) {
      SMBIOS_TABLE_ENTRY_POINT *EntryPoint = (SMBIOS_TABLE_ENTRY_POINT *)Entry->VendorTable;
      if ((EntryPoint == NULL) || (EntryPoint->TableAddress == 0) || (EntryPoint->TableLength == 0)) {
        continue;
      }

      *TableStart  = (CONST UINT8 *)(UINTN)EntryPoint->TableAddress;
      *TableLength = (UINTN)EntryPoint->TableLength;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

STATIC
VOID
UpdateUuidAndSerialFromRecord(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT BOOLEAN            *UuidFound,
  IN OUT BOOLEAN            *SerialFound,
  OUT EFI_GUID              *SystemUuid,
  OUT CHAR8                 *SerialNumber,
  IN UINTN                   SerialBufferLength
  )
{
  if ((Record == NULL) || (Record->Length == 0)) {
    return;
  }

  BOOLEAN NeedUuid   = (UuidFound != NULL) && !(*UuidFound) && (SystemUuid != NULL);
  BOOLEAN NeedSerial = (SerialFound != NULL) && !(*SerialFound) && (SerialNumber != NULL) && (SerialBufferLength > 0);

  if (!NeedUuid && !NeedSerial) {
    return;
  }

  UINT8 CurrentType = Record->Type;

  if (CurrentType == SMBIOS_TYPE_SYSTEM_INFORMATION) {
    CONST SMBIOS_TABLE_TYPE1 *Type1 = (CONST SMBIOS_TABLE_TYPE1 *)Record;

    if (NeedUuid) {
      if ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE1, Uuid) + sizeof(EFI_GUID))) {
        EFI_GUID CandidateUuid;
        CopyMem(&CandidateUuid, &Type1->Uuid, sizeof(EFI_GUID));
        if (IsValidUuid(&CandidateUuid)) {
          CopyMem(SystemUuid, &CandidateUuid, sizeof(EFI_GUID));
          *UuidFound = TRUE;
          NeedUuid   = FALSE;
        }
      }
    }

    if (NeedSerial && ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE1, SerialNumber))) {
      if (TryCopyMeaningfulSmbiosSerial(SerialNumber, SerialBufferLength, Record, Type1->SerialNumber)) {
        *SerialFound = TRUE;
        NeedSerial   = FALSE;
      }
    }
  }

  if (NeedSerial && (CurrentType == SMBIOS_TYPE_BASEBOARD_INFORMATION) &&
      ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE2, SerialNumber))) {
    CONST SMBIOS_TABLE_TYPE2 *Type2 = (CONST SMBIOS_TABLE_TYPE2 *)Record;
    if (TryCopyMeaningfulSmbiosSerial(SerialNumber, SerialBufferLength, Record, Type2->SerialNumber)) {
      *SerialFound = TRUE;
      NeedSerial   = FALSE;
    }
  }

  if (NeedSerial && (CurrentType == SMBIOS_TYPE_SYSTEM_ENCLOSURE) &&
      ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE3, SerialNumber))) {
    CONST SMBIOS_TABLE_TYPE3 *Type3 = (CONST SMBIOS_TABLE_TYPE3 *)Record;
    if (TryCopyMeaningfulSmbiosSerial(SerialNumber, SerialBufferLength, Record, Type3->SerialNumber)) {
      *SerialFound = TRUE;
    }
  }
}

typedef
BOOLEAN
(*SMBIOS_RECORD_VISITOR)(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT VOID               *Context
  );

STATIC
VOID
EnumerateRawSmbiosTable(
  IN CONST UINT8 *TableStart,
  IN UINTN        TableLength,
  IN SMBIOS_RECORD_VISITOR Visitor,
  IN OUT VOID               *Context
  )
{
  if ((TableStart == NULL) || (TableLength == 0) || (Visitor == NULL)) {
    return;
  }

  CONST UINT8 *Current = TableStart;
  CONST UINT8 *End     = TableStart + TableLength;

  while (Current < End) {
    if ((UINTN)(End - Current) < sizeof(SMBIOS_STRUCTURE)) {
      break;
    }

    CONST SMBIOS_STRUCTURE *Header = (CONST SMBIOS_STRUCTURE *)Current;
    UINTN                   StructureLength = (UINTN)Header->Length;

    if (StructureLength == 0) {
      break;
    }

    if ((Current + StructureLength) > End) {
      break;
    }

    if (!Visitor(Header, Context)) {
      break;
    }

    CONST UINT8 *Next = Current + StructureLength;

    while (Next < End) {
      if (*Next == 0) {
        Next++;
        if ((Next < End) && (*Next == 0)) {
          Next++;
          break;
        }

        continue;
      }

      Next++;
    }

    if ((Header->Type == SMBIOS_TYPE_END_OF_TABLE) || (Next >= End)) {
      break;
    }

    Current = Next;
  }
}

typedef struct {
  BOOLEAN   *UuidFound;
  BOOLEAN   *SerialFound;
  EFI_GUID  *SystemUuid;
  CHAR8     *SerialNumber;
  UINTN      SerialBufferLength;
} UUID_SERIAL_CONTEXT;

STATIC
BOOLEAN
UpdateUuidSerialVisitor(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT VOID               *Context
  )
{
  UUID_SERIAL_CONTEXT *State = (UUID_SERIAL_CONTEXT *)Context;

  UpdateUuidAndSerialFromRecord(
    Record,
    State->UuidFound,
    State->SerialFound,
    State->SystemUuid,
    State->SerialNumber,
    State->SerialBufferLength
    );

  if (((State->UuidFound == NULL) || (*(State->UuidFound))) &&
      ((State->SerialFound == NULL) || (*(State->SerialFound)))) {
    return FALSE;
  }

  return TRUE;
}

STATIC
VOID
ScanRawSmbiosTable(
  IN CONST UINT8 *TableStart,
  IN UINTN        TableLength,
  IN OUT BOOLEAN *UuidFound,
  IN OUT BOOLEAN *SerialFound,
  OUT EFI_GUID   *SystemUuid,
  OUT CHAR8      *SerialNumber,
  IN UINTN        SerialBufferLength
  )
{
  if ((TableStart == NULL) || (TableLength == 0)) {
    return;
  }

  UUID_SERIAL_CONTEXT Context;
  Context.UuidFound          = UuidFound;
  Context.SerialFound        = SerialFound;
  Context.SystemUuid         = SystemUuid;
  Context.SerialNumber       = SerialNumber;
  Context.SerialBufferLength = SerialBufferLength;

  EnumerateRawSmbiosTable(TableStart, TableLength, UpdateUuidSerialVisitor, &Context);
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
  BOOLEAN NeedUuid   = (SystemUuid != NULL);
  BOOLEAN NeedSerial = (SerialNumber != NULL) && (SerialBufferLength > 0);

  if (NeedUuid) {
    ZeroMem(SystemUuid, sizeof(EFI_GUID));
  }

  if (NeedSerial) {
    SerialNumber[0] = '\0';
  }

  if (!NeedUuid && !NeedSerial) {
    return;
  }

  BOOLEAN UuidFound   = !NeedUuid;
  BOOLEAN SerialFound = !NeedSerial;

  EFI_SMBIOS_PROTOCOL *Smbios = NULL;
  EFI_STATUS           Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (!EFI_ERROR(Status) && (Smbios != NULL)) {
    EFI_SMBIOS_HANDLE       Handle = SMBIOS_HANDLE_PI_RESERVED;
    EFI_SMBIOS_TABLE_HEADER *Record;

    while (TRUE) {
      Status = Smbios->GetNext(Smbios, &Handle, NULL, &Record, NULL);
      if (EFI_ERROR(Status)) {
        break;
      }

      if (Record == NULL) {
        continue;
      }

      UpdateUuidAndSerialFromRecord(
        (CONST SMBIOS_STRUCTURE *)Record,
        NeedUuid ? &UuidFound : NULL,
        NeedSerial ? &SerialFound : NULL,
        SystemUuid,
        SerialNumber,
        SerialBufferLength
        );

      if (UuidFound && SerialFound) {
        break;
      }
    }
  }

  if (UuidFound && SerialFound) {
    return;
  }

  CONST UINT8 *RawTable       = NULL;
  UINTN        RawTableLength = 0;

  Status = GetSmbiosRawTable(&RawTable, &RawTableLength);
  if (EFI_ERROR(Status) || (RawTable == NULL) || (RawTableLength == 0)) {
    return;
  }

  ScanRawSmbiosTable(
    RawTable,
    RawTableLength,
    NeedUuid ? &UuidFound : NULL,
    NeedSerial ? &SerialFound : NULL,
    SystemUuid,
    SerialNumber,
    SerialBufferLength
    );
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

typedef struct {
  CHAR8 *Buffer;
  UINTN Length;
  UINTN Capacity;
} JSON_STRING_BUILDER;

STATIC
EFI_STATUS
InitializeJsonStringBuilder(
  OUT JSON_STRING_BUILDER *Builder,
  IN UINTN                 InitialCapacity
  )
{
  if ((Builder == NULL) || (InitialCapacity == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Builder->Buffer = AllocateZeroPool(InitialCapacity);
  if (Builder->Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Builder->Length    = 0;
  Builder->Capacity  = InitialCapacity;
  Builder->Buffer[0] = '\0';
  return EFI_SUCCESS;
}

STATIC
VOID
FreeJsonStringBuilder(
  IN OUT JSON_STRING_BUILDER *Builder
  )
{
  if (Builder == NULL) {
    return;
  }

  if (Builder->Buffer != NULL) {
    FreePool(Builder->Buffer);
    Builder->Buffer = NULL;
  }

  Builder->Length   = 0;
  Builder->Capacity = 0;
}

STATIC
EFI_STATUS
JsonBuilderEnsureCapacity(
  IN OUT JSON_STRING_BUILDER *Builder,
  IN UINTN                    AdditionalLength
  )
{
  if (Builder == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (AdditionalLength == 0) {
    return EFI_SUCCESS;
  }

  if (Builder->Buffer == NULL) {
    return EFI_NOT_READY;
  }

  if (Builder->Capacity < Builder->Length) {
    return EFI_BAD_BUFFER_SIZE;
  }

  UINTN Required = Builder->Length + AdditionalLength + 1;
  if (Required <= Builder->Capacity) {
    return EFI_SUCCESS;
  }

  UINTN NewCapacity = Builder->Capacity;
  if (NewCapacity == 0) {
    NewCapacity = Required;
  }

  while (NewCapacity < Required) {
    if (NewCapacity >= MAX_UINTN / 2) {
      NewCapacity = Required;
      break;
    }

    NewCapacity *= 2;
  }

  if (NewCapacity < Required) {
    NewCapacity = Required;
  }

  CHAR8 *NewBuffer = AllocateZeroPool(NewCapacity);
  if (NewBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (Builder->Length > 0) {
    CopyMem(NewBuffer, Builder->Buffer, Builder->Length);
  }

  FreePool(Builder->Buffer);
  Builder->Buffer              = NewBuffer;
  Builder->Capacity            = NewCapacity;
  Builder->Buffer[Builder->Length] = '\0';

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
JsonBuilderAppendBuffer(
  IN OUT JSON_STRING_BUILDER *Builder,
  IN CONST CHAR8             *Buffer,
  IN UINTN                    Length
  )
{
  if ((Builder == NULL) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Length == 0) {
    return EFI_SUCCESS;
  }

  EFI_STATUS Status = JsonBuilderEnsureCapacity(Builder, Length);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  CopyMem(Builder->Buffer + Builder->Length, Buffer, Length);
  Builder->Length += Length;
  Builder->Buffer[Builder->Length] = '\0';

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
JsonBuilderAppendString(
  IN OUT JSON_STRING_BUILDER *Builder,
  IN CONST CHAR8             *String
  )
{
  if ((Builder == NULL) || (String == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return JsonBuilderAppendBuffer(Builder, String, AsciiStrLen(String));
}

STATIC
EFI_STATUS
JsonBuilderAppendChar(
  IN OUT JSON_STRING_BUILDER *Builder,
  IN CHAR8                    Character
  )
{
  return JsonBuilderAppendBuffer(Builder, &Character, 1);
}

STATIC
CHAR8
NibbleToHex(
  IN UINT8 Value
  )
{
  if (Value < 10) {
    return (CHAR8)('0' + Value);
  }

  return (CHAR8)('A' + (Value - 10));
}

STATIC
EFI_STATUS
JsonBuilderAppendJsonString(
  IN OUT JSON_STRING_BUILDER *Builder,
  IN CONST CHAR8             *String
  )
{
  if ((Builder == NULL) || (String == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  EFI_STATUS Status = JsonBuilderAppendChar(Builder, '"');
  if (EFI_ERROR(Status)) {
    return Status;
  }

  while (*String != '\0') {
    CHAR8 Character = *String++;

    switch (Character) {
      case '\\':
      case '"':
        Status = JsonBuilderAppendChar(Builder, '\\');
        if (EFI_ERROR(Status)) {
          return Status;
        }
        Status = JsonBuilderAppendChar(Builder, Character);
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      case '\b':
        Status = JsonBuilderAppendString(Builder, "\\b");
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      case '\f':
        Status = JsonBuilderAppendString(Builder, "\\f");
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      case '\n':
        Status = JsonBuilderAppendString(Builder, "\\n");
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      case '\r':
        Status = JsonBuilderAppendString(Builder, "\\r");
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      case '\t':
        Status = JsonBuilderAppendString(Builder, "\\t");
        if (EFI_ERROR(Status)) {
          return Status;
        }
        break;

      default:
        if ((UINT8)Character < 0x20) {
          CHAR8 Escape[6];
          Escape[0] = '\\';
          Escape[1] = 'u';
          Escape[2] = '0';
          Escape[3] = '0';
          Escape[4] = NibbleToHex((Character >> 4) & 0x0F);
          Escape[5] = NibbleToHex(Character & 0x0F);
          Status    = JsonBuilderAppendBuffer(Builder, Escape, sizeof(Escape));
          if (EFI_ERROR(Status)) {
            return Status;
          }
        } else {
          Status = JsonBuilderAppendChar(Builder, Character);
          if (EFI_ERROR(Status)) {
            return Status;
          }
        }
        break;
    }
  }

  Status = JsonBuilderAppendChar(Builder, '"');
  return Status;
}

STATIC
UINTN
GenerateHardwareIdVariants(
  IN CONST PCI_TYPE00 *Config,
  OUT CHAR8            Variants[][64],
  IN UINTN             MaxVariants
  )
{
  if ((Config == NULL) || (Variants == NULL) || (MaxVariants == 0)) {
    return 0;
  }

  UINT16 VendorId = Config->Hdr.VendorId;
  if (VendorId == 0xFFFF) {
    return 0;
  }

  UINT16 DeviceId   = Config->Hdr.DeviceId;
  UINT8  Revision   = Config->Hdr.RevisionID;
  UINT8  BaseClass  = Config->Hdr.ClassCode[2];
  UINT8  SubClass   = Config->Hdr.ClassCode[1];
  UINT8  ProgIf     = Config->Hdr.ClassCode[0];
  UINTN  Count      = 0;

  BOOLEAN HasSubsystem = FALSE;
  UINT16  SubVendor    = 0;
  UINT16  SubDevice    = 0;

  UINT8 HeaderType = Config->Hdr.HeaderType & 0x7F;
  if (HeaderType == PCI_HEADER_TYPE_DEVICE) {
    SubVendor = Config->Device.SubsystemVendorID;
    SubDevice = Config->Device.SubsystemID;
    if ((SubVendor != 0) && (SubVendor != 0xFFFF) &&
        (SubDevice != 0) && (SubDevice != 0xFFFF)) {
      HasSubsystem = TRUE;
    }
  }

  if (HasSubsystem) {
    if (Count < MaxVariants) {
      AsciiSPrint(
        Variants[Count],
        sizeof(Variants[Count]),
        "PCI\\VEN_%04X&DEV_%04X&SUBSYS_%04X%04X&REV_%02X",
        VendorId,
        DeviceId,
        SubVendor,
        SubDevice,
        Revision
        );
      Count++;
    }

    if (Count < MaxVariants) {
      AsciiSPrint(
        Variants[Count],
        sizeof(Variants[Count]),
        "PCI\\VEN_%04X&DEV_%04X&SUBSYS_%04X%04X",
        VendorId,
        DeviceId,
        SubVendor,
        SubDevice
        );
      Count++;
    }
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\VEN_%04X&DEV_%04X&REV_%02X",
      VendorId,
      DeviceId,
      Revision
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\VEN_%04X&DEV_%04X",
      VendorId,
      DeviceId
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\VEN_%04X&CC_%02X%02X%02X",
      VendorId,
      BaseClass,
      SubClass,
      ProgIf
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\VEN_%04X&CC_%02X%02X",
      VendorId,
      BaseClass,
      SubClass
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\VEN_%04X",
      VendorId
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\CC_%02X%02X%02X",
      BaseClass,
      SubClass,
      ProgIf
      );
    Count++;
  }

  if (Count < MaxVariants) {
    AsciiSPrint(
      Variants[Count],
      sizeof(Variants[Count]),
      "PCI\\CC_%02X%02X",
      BaseClass,
      SubClass
      );
    Count++;
  }

  return Count;
}

STATIC
EFI_STATUS
BuildHardwareInventoryPayload(
  OUT CHAR8 **JsonPayload,
  OUT UINTN *PayloadLength
  )
{
  if ((JsonPayload == NULL) || (PayloadLength == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *JsonPayload   = NULL;
  *PayloadLength = 0;

  if (gBS == NULL) {
    return EFI_NOT_READY;
  }

  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;

  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status)) {
    if (Status != EFI_NOT_FOUND) {
      return Status;
    }

    HandleCount  = 0;
    HandleBuffer = NULL;
  }

  JSON_STRING_BUILDER Builder;
  ZeroMem(&Builder, sizeof(Builder));

  Status = InitializeJsonStringBuilder(&Builder, HARDWARE_INVENTORY_INITIAL_CAPACITY);
  if (EFI_ERROR(Status)) {
    if (HandleBuffer != NULL) {
      FreePool(HandleBuffer);
    }
    return Status;
  }

  Status = JsonBuilderAppendString(&Builder, "{\"devices\":[");
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }

  BOOLEAN FirstDevice = TRUE;

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    EFI_PCI_IO_PROTOCOL *PciIo = NULL;
    Status = gBS->HandleProtocol(HandleBuffer[Index], &gEfiPciIoProtocolGuid, (VOID **)&PciIo);
    if (EFI_ERROR(Status) || (PciIo == NULL)) {
      continue;
    }

    PCI_TYPE00 PciHeader;
    ZeroMem(&PciHeader, sizeof(PciHeader));

    Status = PciIo->Pci.Read(
                         PciIo,
                         EfiPciIoWidthUint32,
                         0,
                         sizeof(PciHeader) / sizeof(UINT32),
                         &PciHeader
                         );
    if (EFI_ERROR(Status)) {
      continue;
    }

    CHAR8 HardwareIds[MAX_HARDWARE_ID_VARIANTS][64];
    UINTN VariantCount = GenerateHardwareIdVariants(&PciHeader, HardwareIds, MAX_HARDWARE_ID_VARIANTS);
    if (VariantCount == 0) {
      continue;
    }

    UINTN Segment  = 0;
    UINTN Bus      = 0;
    UINTN Device   = 0;
    UINTN Function = 0;

    if (PciIo->GetLocation != NULL) {
      EFI_STATUS LocationStatus = PciIo->GetLocation(PciIo, &Segment, &Bus, &Device, &Function);
      if (EFI_ERROR(LocationStatus)) {
        Segment  = 0;
        Bus      = 0;
        Device   = 0;
        Function = 0;
      }
    }

    CHAR8 Location[32];
    AsciiSPrint(
      Location,
      sizeof(Location),
      "%04X:%02X:%02X.%u",
      (UINT32)Segment,
      (UINT32)Bus,
      (UINT32)Device,
      (UINT32)Function
      );

    if (!FirstDevice) {
      Status = JsonBuilderAppendChar(&Builder, ',');
      if (EFI_ERROR(Status)) {
        goto Cleanup;
      }
    }

    FirstDevice = FALSE;

    Status = JsonBuilderAppendString(&Builder, "{\"location\":");
    if (EFI_ERROR(Status)) {
      goto Cleanup;
    }

    Status = JsonBuilderAppendJsonString(&Builder, Location);
    if (EFI_ERROR(Status)) {
      goto Cleanup;
    }

    Status = JsonBuilderAppendString(&Builder, ",\"hardware_ids\":[");
    if (EFI_ERROR(Status)) {
      goto Cleanup;
    }

    for (UINTN VariantIndex = 0; VariantIndex < VariantCount; VariantIndex++) {
      if (VariantIndex != 0) {
        Status = JsonBuilderAppendChar(&Builder, ',');
        if (EFI_ERROR(Status)) {
          goto Cleanup;
        }
      }

      Status = JsonBuilderAppendJsonString(&Builder, HardwareIds[VariantIndex]);
      if (EFI_ERROR(Status)) {
        goto Cleanup;
      }
    }

    Status = JsonBuilderAppendString(&Builder, "]}");
    if (EFI_ERROR(Status)) {
      goto Cleanup;
    }
  }

  Status = JsonBuilderAppendString(&Builder, "]}");
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }

  *JsonPayload   = Builder.Buffer;
  *PayloadLength = Builder.Length;

  Builder.Buffer   = NULL;
  Builder.Length   = 0;
  Builder.Capacity = 0;

  Status = EFI_SUCCESS;

Cleanup:
  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }

  if (Builder.Buffer != NULL) {
    FreeJsonStringBuilder(&Builder);
  }

  return Status;
}

STATIC
EFI_STATUS
BuildJsonPayload(
  OUT CHAR8       *JsonBuffer,
  IN  UINTN        JsonBufferSize,
  IN  CONST CHAR8 *UuidString,
  IN  CONST CHAR8 *MacString,
  IN  CONST CHAR8 *SerialNumber,
  IN  CONST CHAR8 *CpuModel,
  IN  CONST CHAR8 *CpuSize,
  IN  CONST CHAR8 *BoardModel,
  IN  CONST CHAR8 *BoardSize,
  IN  CONST CHAR8 *MemoryModel,
  IN  CONST CHAR8 *MemorySize
  )
{
  if ((JsonBuffer == NULL) || (JsonBufferSize == 0) ||
      (UuidString == NULL) || (MacString == NULL) || (SerialNumber == NULL) ||
      (CpuModel == NULL) || (CpuSize == NULL) ||
      (BoardModel == NULL) || (BoardSize == NULL) ||
      (MemoryModel == NULL) || (MemorySize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  INTN Result = AsciiSPrint(
                   JsonBuffer,
                   JsonBufferSize,
                   "{\"uuid\":\"%a\",\"mac\":\"%a\",\"serial_number\":\"%a\"," \
                   "\"cpu\":{\"model\":\"%a\",\"size\":\"%a\"}," \
                   "\"motherboard\":{\"model\":\"%a\",\"size\":\"%a\"}," \
                   "\"memory\":{\"model\":\"%a\",\"size\":\"%a\"}}",
                   UuidString,
                   MacString,
                   SerialNumber,
                   CpuModel,
                   CpuSize,
                   BoardModel,
                   BoardSize,
                   MemoryModel,
                   MemorySize
                   );

  if (Result < 0) {
    return EFI_DEVICE_ERROR;
  }

  if ((UINTN)Result >= JsonBufferSize) {
    return EFI_BUFFER_TOO_SMALL;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ExtractServerUrlFromDhcpPacket(
  IN  CONST EFI_DHCP4_PACKET *Packet,
  OUT CHAR16                 **ServerUrl
  )
{
  if ((Packet == NULL) || (ServerUrl == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *ServerUrl = NULL;

  if (Packet->Length <= OFFSET_OF(EFI_DHCP4_PACKET, Dhcp4.Option)) {
    return EFI_NOT_FOUND;
  }

  CONST UINT8 *Option = Packet->Dhcp4.Option;
  CONST UINT8 *End    = ((CONST UINT8 *)Packet) + Packet->Length;

  while (Option < End) {
    UINT8 OptionCode = *Option++;

    if (OptionCode == DHCP_OPTION_PAD) {
      continue;
    }

    if (OptionCode == DHCP_OPTION_END) {
      break;
    }

    if (Option >= End) {
      break;
    }

    UINT8 OptionLength = *Option++;
    if ((Option + OptionLength) > End) {
      break;
    }

    if (OptionCode == COMPUTER_INFO_QR_SERVER_URL_OPTION) {
      if (OptionLength == 0) {
        return EFI_NOT_FOUND;
      }

      CHAR8 *AsciiUrl = AllocateZeroPool(OptionLength + 1);
      if (AsciiUrl == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }

      CopyMem(AsciiUrl, Option, OptionLength);

      CHAR16 *UnicodeUrl = AllocateZeroPool((OptionLength + 1) * sizeof(CHAR16));
      if (UnicodeUrl == NULL) {
        FreePool(AsciiUrl);
        return EFI_OUT_OF_RESOURCES;
      }

      EFI_STATUS Status = AsciiStrToUnicodeStrS(AsciiUrl, UnicodeUrl, OptionLength + 1);
      FreePool(AsciiUrl);
      if (EFI_ERROR(Status)) {
        FreePool(UnicodeUrl);
        return Status;
      }

      *ServerUrl = UnicodeUrl;
      return EFI_SUCCESS;
    }

    Option += OptionLength;
  }

  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
GetServerUrlFromDhcp(
  OUT CHAR16 **ServerUrl
  )
{
  if (ServerUrl == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *ServerUrl = NULL;

  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;

  EFI_STATUS Status = gBS->LocateHandleBuffer(
                          ByProtocol,
                          &gEfiDhcp4ProtocolGuid,
                          NULL,
                          &HandleCount,
                          &HandleBuffer
                          );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  EFI_STATUS Result = EFI_NOT_FOUND;

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    Status = InitializeNicOnHandle(HandleBuffer[Index]);
    if (EFI_ERROR(Status)) {
      if ((Result == EFI_NOT_FOUND) && (Status != EFI_NOT_FOUND)) {
        Result = Status;
      }
      continue;
    }

    EFI_DHCP4_PROTOCOL *Dhcp4 = NULL;
    Status = gBS->HandleProtocol(
                    HandleBuffer[Index],
                    &gEfiDhcp4ProtocolGuid,
                    (VOID **)&Dhcp4
                    );
    if (EFI_ERROR(Status) || (Dhcp4 == NULL)) {
      continue;
    }

    EFI_DHCP4_MODE_DATA ModeData;
    ZeroMem(&ModeData, sizeof(ModeData));

    if (Dhcp4->GetModeData == NULL) {
      if (Result == EFI_NOT_FOUND) {
        Result = EFI_UNSUPPORTED;
      }
      continue;
    }

    Status = Dhcp4->GetModeData(Dhcp4, &ModeData);
    if (EFI_ERROR(Status)) {
      continue;
    }

    EFI_DHCP4_STATE OriginalState = ModeData.State;
    Status = StartDhcpClientIfStopped(Dhcp4, &ModeData, NULL);
    if (EFI_ERROR(Status)) {
      if ((Result == EFI_NOT_FOUND) && (Status != EFI_NOT_FOUND)) {
        Result = Status;
      }
      if (OriginalState == Dhcp4Stopped) {
        continue;
      }
    }

    if (ModeData.ReplyPacket == NULL) {
      continue;
    }

    Status = ExtractServerUrlFromDhcpPacket(ModeData.ReplyPacket, ServerUrl);
    if (!EFI_ERROR(Status) && (*ServerUrl != NULL)) {
      Result = EFI_SUCCESS;
      break;
    }

    if ((Result == EFI_NOT_FOUND) && (Status != EFI_NOT_FOUND)) {
      Result = Status;
    }
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }

  if (EFI_ERROR(Result) && (*ServerUrl != NULL)) {
    FreePool(*ServerUrl);
    *ServerUrl = NULL;
  }

  return Result;
}

STATIC
CONST CHAR16 *
Dhcp4StateToString(
  IN EFI_DHCP4_STATE State
  )
{
  switch (State) {
    case Dhcp4Stopped:
      return L"Stopped";
    case Dhcp4Init:
      return L"Init";
    case Dhcp4Selecting:
      return L"Selecting";
    case Dhcp4Requesting:
      return L"Requesting";
    case Dhcp4Bound:
      return L"Bound";
    case Dhcp4Renewing:
      return L"Renewing";
    case Dhcp4Rebinding:
      return L"Rebinding";
    case Dhcp4InitReboot:
      return L"Init-Reboot";
    case Dhcp4Rebooting:
      return L"Rebooting";
    default:
      return L"Unknown";
  }
}

STATIC
VOID
Ipv4AddressToString(
  IN  CONST EFI_IPv4_ADDRESS *Address,
  OUT CHAR16                 *Buffer,
  IN  UINTN                   BufferSize
  )
{
  if ((Buffer == NULL) || (BufferSize < (IPV4_STRING_BUFFER_LENGTH * sizeof(CHAR16)))) {
    return;
  }

  Buffer[0] = L'\0';

  if (Address == NULL) {
    UnicodeSPrint(Buffer, BufferSize, L"0.0.0.0");
    return;
  }

  UnicodeSPrint(
    Buffer,
    BufferSize,
    L"%u.%u.%u.%u",
    (UINT32)Address->Addr[0],
    (UINT32)Address->Addr[1],
    (UINT32)Address->Addr[2],
    (UINT32)Address->Addr[3]
    );
}

STATIC
VOID
PauseWithPrompt(
  IN CONST CHAR16 *Prompt,
  IN CONST CHAR16 *ErrorPrefix OPTIONAL
  )
{
  EFI_STATUS Status;

  if (!mWaitForKeyPressSupported) {
    return;
  }

  if (Prompt != NULL) {
    Print(L"%s", Prompt);
  }

  Status = WaitForKeyPress(NULL);
  if (EFI_ERROR(Status)) {
    if (ErrorPrefix != NULL) {
      Print(L"%sUnable to read key press: %r\n", ErrorPrefix, Status);
    } else {
      Print(L"Unable to read key press: %r\n", Status);
    }

    mWaitForKeyPressSupported = FALSE;
  }
}

STATIC
VOID
PrintDhcpOptions(
  IN CONST EFI_DHCP4_PACKET *Packet
  )
{
  if ((Packet == NULL) || (Packet->Length <= OFFSET_OF(EFI_DHCP4_PACKET, Dhcp4.Option))) {
    Print(L"    No DHCP options available.\n");
    return;
  }

  CONST UINT8 *Option         = Packet->Dhcp4.Option;
  CONST UINT8 *End            = ((CONST UINT8 *)Packet) + Packet->Length;
  CHAR16       AsciiBuffer[DHCP_OPTION_MAX_LENGTH + 1];
  UINTN        OptionsPrinted = 0;

  while (Option < End) {
    UINT8 OptionCode = *Option++;

    if (OptionCode == DHCP_OPTION_PAD) {
      Print(L"    Option 0 (Pad)\n");
      OptionsPrinted++;
      if (((OptionsPrinted % 4) == 0) && (Option < End)) {
        PauseWithPrompt(L"    Press any key to view more DHCP options...\n", L"    ");
      }

      continue;
    }

    if (OptionCode == DHCP_OPTION_END) {
      Print(L"    Option 255 (End)\n");
      OptionsPrinted++;
      break;
    }

    if (Option >= End) {
      Print(L"    Malformed DHCP option detected after code %u.\n", (UINT32)OptionCode);
      break;
    }

    UINT8 OptionLength = *Option++;
    if ((Option + OptionLength) > End) {
      Print(
        L"    Malformed DHCP option %u length %u exceeds packet boundary.\n",
        (UINT32)OptionCode,
        (UINT32)OptionLength
        );
      break;
    }

    Print(L"    Option %u (0x%02X), length %u\n", (UINT32)OptionCode, (UINT32)OptionCode, (UINT32)OptionLength);

    if (OptionLength == 0) {
      Print(L"      Data: (none)\n");
    } else {
      Print(L"      Data:");
      for (UINTN ByteIndex = 0; ByteIndex < OptionLength; ByteIndex++) {
        Print(L" %02X", (UINT32)Option[ByteIndex]);
      }
      Print(L"\n");

      UINTN CopyLength = OptionLength;
      if (CopyLength > DHCP_OPTION_MAX_LENGTH) {
        CopyLength = DHCP_OPTION_MAX_LENGTH;
      }

      for (UINTN ByteIndex = 0; ByteIndex < CopyLength; ByteIndex++) {
        CHAR8 Value = (CHAR8)Option[ByteIndex];
        if ((Value >= 0x20) && (Value <= 0x7E)) {
          AsciiBuffer[ByteIndex] = (CHAR16)Value;
        } else {
          AsciiBuffer[ByteIndex] = L'.';
        }
      }
      AsciiBuffer[CopyLength] = L'\0';

      Print(L"      ASCII: %s\n", AsciiBuffer);
    }

    Option += OptionLength;
    OptionsPrinted++;

    if (((OptionsPrinted % 4) == 0) && (Option < End)) {
      PauseWithPrompt(L"    Press any key to view more DHCP options...\n", L"    ");
    }
  }
}

STATIC
EFI_STATUS
GetControllerHandleForChildProtocol(
  IN  EFI_HANDLE ChildHandle,
  IN  EFI_GUID   *ProtocolGuid,
  OUT EFI_HANDLE *ControllerHandle
  )
{
  if ((ChildHandle == NULL) || (ProtocolGuid == NULL) || (ControllerHandle == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *ControllerHandle = NULL;

  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *OpenInfo   = NULL;
  UINTN                                EntryCount = 0;

  EFI_STATUS Status = gBS->OpenProtocolInformation(
                          ChildHandle,
                          ProtocolGuid,
                          &OpenInfo,
                          &EntryCount
                          );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  EFI_STATUS Result = EFI_NOT_FOUND;

  for (UINTN Index = 0; Index < EntryCount; Index++) {
    EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *Entry = &OpenInfo[Index];
    if ((Entry->Attributes & EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER) != 0) {
      if (Entry->ControllerHandle != NULL) {
        *ControllerHandle = Entry->ControllerHandle;
        Result            = EFI_SUCCESS;
        break;
      }
    }
  }

  if (OpenInfo != NULL) {
    FreePool(OpenInfo);
  }

  return Result;
}

STATIC
EFI_STATUS
OpenSimpleNetworkProtocolForHandle(
  IN  EFI_HANDLE                    Handle,
  OUT EFI_SIMPLE_NETWORK_PROTOCOL **Snp,
  OUT EFI_HANDLE                   *ProviderHandle OPTIONAL,
  OUT EFI_HANDLE                   *ControllerHandle OPTIONAL
  )
{
  if ((Handle == NULL) || (Snp == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Snp = NULL;
  if (ProviderHandle != NULL) {
    *ProviderHandle = NULL;
  }
  if (ControllerHandle != NULL) {
    *ControllerHandle = NULL;
  }

  EFI_SIMPLE_NETWORK_PROTOCOL *LocalSnp      = NULL;
  EFI_HANDLE                   LocalController;
  EFI_STATUS                   Status;
  EFI_STATUS                   ProtocolStatus;
  EFI_STATUS                   ControllerStatus;

  Status = gBS->HandleProtocol(
                  Handle,
                  &gEfiSimpleNetworkProtocolGuid,
                  (VOID **)&LocalSnp
                  );
  ProtocolStatus = Status;

  if (!EFI_ERROR(Status) && (LocalSnp != NULL)) {
    *Snp = LocalSnp;
    if (ProviderHandle != NULL) {
      *ProviderHandle = Handle;
    }
  } else {
    LocalSnp = NULL;
  }

  LocalController = NULL;
  ControllerStatus = GetControllerHandleForChildProtocol(
                       Handle,
                       &gEfiDhcp4ProtocolGuid,
                       &LocalController
                       );
  if (!EFI_ERROR(ControllerStatus) && (ControllerHandle != NULL)) {
    *ControllerHandle = LocalController;
  }

  if (*Snp != NULL) {
    return EFI_SUCCESS;
  }

  if (!EFI_ERROR(ControllerStatus) && (LocalController != NULL)) {
    Status = gBS->HandleProtocol(
                    LocalController,
                    &gEfiSimpleNetworkProtocolGuid,
                    (VOID **)&LocalSnp
                    );
    ProtocolStatus = Status;
    if (!EFI_ERROR(Status) && (LocalSnp != NULL)) {
      *Snp = LocalSnp;
      if (ProviderHandle != NULL) {
        *ProviderHandle = LocalController;
      }
      return EFI_SUCCESS;
    }
  }

  if (EFI_ERROR(ProtocolStatus)) {
    return ProtocolStatus;
  }

  if (EFI_ERROR(ControllerStatus)) {
    return ControllerStatus;
  }

  return EFI_DEVICE_ERROR;
}

STATIC
EFI_STATUS
StartSimpleNetworkProtocolInstance(
  IN EFI_SIMPLE_NETWORK_PROTOCOL *Snp
  )
{
  if (Snp == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Snp->Mode == NULL) {
    return EFI_DEVICE_ERROR;
  }

  EFI_SIMPLE_NETWORK_STATE State = Snp->Mode->State;

  if (State == EfiSimpleNetworkInitialized) {
    return EFI_SUCCESS;
  }

  if (State == EfiSimpleNetworkStopped) {
    if (Snp->Start == NULL) {
      return EFI_UNSUPPORTED;
    }

    EFI_STATUS Status = Snp->Start(Snp);
    if ((Status != EFI_SUCCESS) && (Status != EFI_ALREADY_STARTED)) {
      return Status;
    }

    State = Snp->Mode->State;
  }

  if (State != EfiSimpleNetworkInitialized) {
    if (Snp->Initialize == NULL) {
      return EFI_UNSUPPORTED;
    }

    EFI_STATUS Status = Snp->Initialize(Snp, 0, 0);
    if ((Status != EFI_SUCCESS) && (Status != EFI_ALREADY_STARTED)) {
      return Status;
    }

    State = Snp->Mode->State;
  }

  if ((State != EfiSimpleNetworkInitialized) && (State != EfiSimpleNetworkStarted)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ConnectNetworkController(
  IN EFI_HANDLE ControllerHandle
  )
{
  if (ControllerHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EFI_STATUS Status = gBS->ConnectController(
                          ControllerHandle,
                          NULL,
                          NULL,
                          TRUE
                          );
  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  return Status;
}

STATIC
VOID
FreeDhcpHandleBuffer(
  IN EFI_HANDLE *HandleBuffer
  )
{
  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }
}

STATIC
EFI_STATUS
LocateDhcp4Handles(
  OUT EFI_HANDLE **HandleBuffer,
  OUT UINTN      *HandleCount
  )
{
  if ((HandleBuffer == NULL) || (HandleCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *HandleBuffer = NULL;
  *HandleCount  = 0;

  EFI_STATUS Status = gBS->LocateHandleBuffer(
                             ByProtocol,
                             &gEfiDhcp4ProtocolGuid,
                             NULL,
                             HandleCount,
                             HandleBuffer
                             );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if ((*HandleBuffer == NULL) || (*HandleCount == 0)) {
    if (*HandleBuffer != NULL) {
      FreeDhcpHandleBuffer(*HandleBuffer);
      *HandleBuffer = NULL;
    }
    *HandleCount = 0;
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
StartDhcpClientIfStopped(
  IN     EFI_DHCP4_PROTOCOL *Dhcp4,
  IN OUT EFI_DHCP4_MODE_DATA *ModeData,
  OUT    BOOLEAN            *ClientStarted OPTIONAL
  )
{
  if ((Dhcp4 == NULL) || (ModeData == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (ModeData->State != Dhcp4Stopped) {
    return EFI_SUCCESS;
  }

  if (Dhcp4->Start == NULL) {
    return EFI_UNSUPPORTED;
  }

  EFI_STATUS Status = Dhcp4->Start(Dhcp4, NULL);

  if (Status == EFI_NOT_STARTED) {
    if (Dhcp4->Configure == NULL) {
      return EFI_UNSUPPORTED;
    }

    EFI_DHCP4_CONFIG_DATA ConfigData;
    ZeroMem(&ConfigData, sizeof(ConfigData));

    if (!mDhcpParameterRequestListInitialized) {
      EFI_DHCP4_PACKET_OPTION *ParameterRequestList;

      ParameterRequestList = (EFI_DHCP4_PACKET_OPTION *)mDhcpParameterRequestBuffer;

      ZeroMem(mDhcpParameterRequestBuffer, sizeof(mDhcpParameterRequestBuffer));
      ParameterRequestList->OpCode = DHCP_OPTION_PARAMETER_REQUEST_LIST;
      ParameterRequestList->Length = (UINT8)sizeof(mDhcpParameterRequestOptions);
      CopyMem(
        ParameterRequestList->Data,
        mDhcpParameterRequestOptions,
        sizeof(mDhcpParameterRequestOptions)
        );

      mDhcpParameterRequestOptionList[0] = ParameterRequestList;
      mDhcpParameterRequestListInitialized = TRUE;
    }

    if (mDhcpParameterRequestOptionList[0] == NULL) {
      return EFI_DEVICE_ERROR;
    }

    ConfigData.OptionCount = 1;
    ConfigData.OptionList  = mDhcpParameterRequestOptionList;

    Status = Dhcp4->Configure(Dhcp4, &ConfigData);
    if (EFI_ERROR(Status)) {
      return Status;
    }

    Status = Dhcp4->Start(Dhcp4, NULL);
  }

  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (ClientStarted != NULL) {
    *ClientStarted = TRUE;
  }

  if (Dhcp4->GetModeData == NULL) {
    return EFI_UNSUPPORTED;
  }

  ZeroMem(ModeData, sizeof(*ModeData));
  Status = Dhcp4->GetModeData(Dhcp4, ModeData);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
InitializeNicOnHandle(
  IN EFI_HANDLE Handle
  )
{
  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EFI_SIMPLE_NETWORK_PROTOCOL *Snp             = NULL;
  EFI_HANDLE                   ProviderHandle  = NULL;
  EFI_HANDLE                   ControllerHandle = NULL;

  EFI_STATUS Status = OpenSimpleNetworkProtocolForHandle(
                         Handle,
                         &Snp,
                         &ProviderHandle,
                         &ControllerHandle
                         );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = StartSimpleNetworkProtocolInstance(Snp);
  if (Status != EFI_UNSUPPORTED) {
    return Status;
  }

  EFI_HANDLE ConnectHandle = ControllerHandle;
  if (ConnectHandle == NULL) {
    ConnectHandle = ProviderHandle;
  }

  if (ConnectHandle == NULL) {
    return EFI_SUCCESS;
  }

  EFI_STATUS ConnectStatus = ConnectNetworkController(ConnectHandle);
  if (EFI_ERROR(ConnectStatus)) {
    return ConnectStatus;
  }

  EFI_SIMPLE_NETWORK_PROTOCOL *RefreshedSnp = NULL;
  EFI_STATUS                   ReopenStatus;

  ReopenStatus = EFI_UNSUPPORTED;
  if (ProviderHandle != NULL) {
    ReopenStatus = gBS->HandleProtocol(
                             ProviderHandle,
                             &gEfiSimpleNetworkProtocolGuid,
                             (VOID **)&RefreshedSnp
                             );
  }

  if (EFI_ERROR(ReopenStatus) || (RefreshedSnp == NULL) || (RefreshedSnp->Mode == NULL)) {
    ReopenStatus = gBS->HandleProtocol(
                             ConnectHandle,
                             &gEfiSimpleNetworkProtocolGuid,
                             (VOID **)&RefreshedSnp
                             );
  }

  if (EFI_ERROR(ReopenStatus) || (RefreshedSnp == NULL)) {
    return EFI_DEVICE_ERROR;
  }

  EFI_STATUS FinalStatus = StartSimpleNetworkProtocolInstance(RefreshedSnp);
  if (FinalStatus == EFI_UNSUPPORTED) {
    FinalStatus = EFI_SUCCESS;
  }

  return FinalStatus;
}

STATIC
VOID
DisplayDhcpInterfaceInformation(
  IN EFI_HANDLE Handle,
  IN UINTN      Index
  )
{
  EFI_STATUS Status;

  Print(L"DHCPv4 Interface %u\n", (UINT32)(Index + 1));
  Print(L"---------------------\n");
  Print(L"  Handle: %p\n", Handle);

  Status = InitializeNicOnHandle(Handle);
  if (Status == EFI_UNSUPPORTED) {
    Print(L"  Network interface initialization is not supported; continuing with available information.\n");
  } else if (EFI_ERROR(Status)) {
    Print(L"  Unable to initialize network interface: %r\n\n", Status);
    return;
  }

  EFI_DHCP4_PROTOCOL *Dhcp4 = NULL;
  Status = gBS->HandleProtocol(
                      Handle,
                      &gEfiDhcp4ProtocolGuid,
                      (VOID **)&Dhcp4
                      );
  if (EFI_ERROR(Status) || (Dhcp4 == NULL)) {
    Print(L"  Unable to open EFI_DHCP4_PROTOCOL: %r\n\n", Status);
    return;
  }

  EFI_DHCP4_MODE_DATA ModeData;
  ZeroMem(&ModeData, sizeof(ModeData));

  Status = Dhcp4->GetModeData(Dhcp4, &ModeData);
  if (EFI_ERROR(Status)) {
    Print(L"  GetModeData failed: %r\n\n", Status);
    return;
  }

  EFI_DHCP4_STATE OriginalState = ModeData.State;
  Status = StartDhcpClientIfStopped(Dhcp4, &ModeData, NULL);
  if (EFI_ERROR(Status) && (OriginalState == Dhcp4Stopped)) {
    Print(L"  Unable to start DHCP client: %r\n", Status);
  }

  Print(L"  State: %s (%u)\n", Dhcp4StateToString(ModeData.State), (UINT32)ModeData.State);

  UINTN                        MacAddressSize = 0;
  EFI_SIMPLE_NETWORK_PROTOCOL *SnpInfo        = NULL;
  Status = OpenSimpleNetworkProtocolForHandle(
                      Handle,
                      &SnpInfo,
                      NULL,
                      NULL
                      );
  if (!EFI_ERROR(Status) && (SnpInfo != NULL) && (SnpInfo->Mode != NULL)) {
    MacAddressSize = SnpInfo->Mode->HwAddressSize;
  }
  if ((MacAddressSize == 0) && (ModeData.ReplyPacket != NULL)) {
    MacAddressSize = ModeData.ReplyPacket->Dhcp4.Header.HwAddrLen;
  }
  if (MacAddressSize > MAC_ADDRESS_MAX_BYTES) {
    MacAddressSize = MAC_ADDRESS_MAX_BYTES;
  }

  CHAR8 MacString[MAC_STRING_BUFFER_LENGTH];
  MacAddressToString(&ModeData.ClientMacAddress, MacAddressSize, MacString, sizeof(MacString));
  if (MacString[0] == '\0') {
    AsciiStrCpyS(MacString, sizeof(MacString), UNKNOWN_STRING);
  }
  Print(L"  Client MAC: %a\n", MacString);

  CHAR16 AddressString[IPV4_STRING_BUFFER_LENGTH];

  Ipv4AddressToString(&ModeData.ClientAddress, AddressString, sizeof(AddressString));
  Print(L"  Client IP: %s\n", AddressString);

  Ipv4AddressToString(&ModeData.ServerAddress, AddressString, sizeof(AddressString));
  Print(L"  DHCP Server: %s\n", AddressString);

  Ipv4AddressToString(&ModeData.RouterAddress, AddressString, sizeof(AddressString));
  Print(L"  Router: %s\n", AddressString);

  Ipv4AddressToString(&ModeData.SubnetMask, AddressString, sizeof(AddressString));
  Print(L"  Subnet Mask: %s\n", AddressString);

  if (ModeData.LeaseTime == 0xFFFFFFFF) {
    Print(L"  Lease Time: Infinite\n");
  } else {
    Print(L"  Lease Time: %u seconds\n", (UINT32)ModeData.LeaseTime);
  }

  if (ModeData.ReplyPacket != NULL) {
    Print(L"  DHCP Reply Packet Length: %u bytes\n", ModeData.ReplyPacket->Length);
    Print(L"  DHCP Transaction ID: 0x%08X\n", ModeData.ReplyPacket->Dhcp4.Header.Xid);

    Ipv4AddressToString(&ModeData.ReplyPacket->Dhcp4.Header.YourAddr, AddressString, sizeof(AddressString));
    Print(L"  Assigned IP (packet): %s\n", AddressString);

    Ipv4AddressToString(&ModeData.ReplyPacket->Dhcp4.Header.ServerAddr, AddressString, sizeof(AddressString));
    Print(L"  Server IP (packet): %s\n", AddressString);

    Ipv4AddressToString(&ModeData.ReplyPacket->Dhcp4.Header.GatewayAddr, AddressString, sizeof(AddressString));
    Print(L"  Gateway IP (packet): %s\n", AddressString);

    CHAR8 ServerName[sizeof(ModeData.ReplyPacket->Dhcp4.Header.ServerName) + 1];
    ZeroMem(ServerName, sizeof(ServerName));
    CopyMem(
      ServerName,
      ModeData.ReplyPacket->Dhcp4.Header.ServerName,
      sizeof(ModeData.ReplyPacket->Dhcp4.Header.ServerName)
      );
    if (ServerName[0] != '\0') {
      Print(L"  DHCP Server Name: %a\n", ServerName);
    }

    CHAR8 BootFileName[sizeof(ModeData.ReplyPacket->Dhcp4.Header.BootFileName) + 1];
    ZeroMem(BootFileName, sizeof(BootFileName));
    CopyMem(
      BootFileName,
      ModeData.ReplyPacket->Dhcp4.Header.BootFileName,
      sizeof(ModeData.ReplyPacket->Dhcp4.Header.BootFileName)
      );
    if (BootFileName[0] != '\0') {
      Print(L"  Boot File Name: %a\n", BootFileName);
    }

    PauseWithPrompt(L"  Press any key to view DHCP options...\n", L"  ");
    Print(L"  DHCP Options:\n");
    PrintDhcpOptions(ModeData.ReplyPacket);
  } else {
    Print(L"  No DHCP reply packet cached for this interface.\n");
  }

  Print(L"\n");
}

STATIC
EFI_STATUS
RenewDhcpLeaseOnHandle(
  IN  EFI_HANDLE Handle,
  OUT BOOLEAN    *ClientStarted OPTIONAL
  )
{
  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (ClientStarted != NULL) {
    *ClientStarted = FALSE;
  }

  EFI_STATUS Status = InitializeNicOnHandle(Handle);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  EFI_DHCP4_PROTOCOL *Dhcp4 = NULL;

  Status = gBS->HandleProtocol(
                      Handle,
                      &gEfiDhcp4ProtocolGuid,
                      (VOID **)&Dhcp4
                      );
  if (EFI_ERROR(Status) || (Dhcp4 == NULL)) {
    if (!EFI_ERROR(Status)) {
      Status = EFI_DEVICE_ERROR;
    }
    return Status;
  }

  EFI_DHCP4_MODE_DATA ModeData;
  ZeroMem(&ModeData, sizeof(ModeData));

  if (Dhcp4->GetModeData == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = Dhcp4->GetModeData(Dhcp4, &ModeData);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = StartDhcpClientIfStopped(Dhcp4, &ModeData, ClientStarted);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (ModeData.State == Dhcp4Stopped) {
    return EFI_DEVICE_ERROR;
  }

  switch (ModeData.State) {
    case Dhcp4Init:
    case Dhcp4Selecting:
    case Dhcp4Requesting:
    case Dhcp4InitReboot:
    case Dhcp4Rebooting:
      return EFI_NOT_READY;
    default:
      break;
  }

  if (Dhcp4->RenewRebind == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = Dhcp4->RenewRebind(Dhcp4, FALSE, NULL);
  if (Status == EFI_NO_MAPPING) {
    Status = Dhcp4->RenewRebind(Dhcp4, TRUE, NULL);
  }

  return Status;
}

STATIC
VOID
RenewDhcpLeases(
  IN EFI_HANDLE *HandleBuffer,
  IN UINTN       HandleCount
  )
{
  if ((HandleBuffer == NULL) || (HandleCount == 0)) {
    return;
  }

  Print(L"Attempting to renew DHCP lease(s)...\n");

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    BOOLEAN    ClientStarted = FALSE;
    EFI_STATUS Status        = RenewDhcpLeaseOnHandle(HandleBuffer[Index], &ClientStarted);
    if (EFI_ERROR(Status)) {
      switch (Status) {
        case EFI_NOT_READY:
          Print(
            L"  Interface %u: DHCP client does not have an active lease yet; skipping renewal.\n",
            (UINT32)(Index + 1)
            );
          break;
        case EFI_UNSUPPORTED:
          Print(
            L"  Interface %u: DHCP driver does not support Renew/Rebind operations.\n",
            (UINT32)(Index + 1)
            );
          break;
        default:
          Print(
            L"  Interface %u: Failed to renew DHCP lease: %r\n",
            (UINT32)(Index + 1),
            Status
            );
          break;
      }
    } else {
      if (ClientStarted) {
        Print(
          L"  Interface %u: DHCP client started and lease renewal requested successfully.\n",
          (UINT32)(Index + 1)
          );
      } else {
        Print(
          L"  Interface %u: DHCP lease renewal requested successfully.\n",
          (UINT32)(Index + 1)
          );
      }
    }
  }

  Print(L"\n");
}

STATIC
VOID
RenewDhcpLeasesFromMenu(
  VOID
  )
{
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;
  EFI_STATUS  Status;

  Print(L"Collecting DHCPv4 interfaces...\n\n");

  Status = LocateDhcp4Handles(&HandleBuffer, &HandleCount);
  if (EFI_ERROR(Status)) {
    if (Status == EFI_NOT_FOUND) {
      Print(L"No DHCPv4 interfaces found.\n");
    } else {
      Print(L"Unable to locate DHCPv4 handles: %r\n", Status);
    }

    Print(L"\nPress any key to return to the menu...\n");
    WaitForKeyPress(NULL);
    goto Cleanup;
  }

  RenewDhcpLeases(HandleBuffer, HandleCount);

  Print(L"Updated networking information:\n\n");
  for (UINTN Index = 0; Index < HandleCount; Index++) {
    DisplayDhcpInterfaceInformation(HandleBuffer[Index], Index);
  }

  Print(L"Press any key to return to the menu...\n");
  WaitForKeyPress(NULL);

Cleanup:
  FreeDhcpHandleBuffer(HandleBuffer);
}

STATIC
VOID
ShowNetworkInformation(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;

  Print(L"Collecting networking information...\n\n");

  Status = LocateDhcp4Handles(&HandleBuffer, &HandleCount);
  if (EFI_ERROR(Status)) {
    if (Status == EFI_NOT_FOUND) {
      Print(L"No DHCPv4 interfaces found.\n");
    } else {
      Print(L"Unable to locate DHCPv4 handles: %r\n", Status);
    }

    Print(L"\nPress any key to return to the menu...\n");
    WaitForKeyPress(NULL);
    goto Cleanup;
  }

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    DisplayDhcpInterfaceInformation(HandleBuffer[Index], Index);
  }

  Print(L"Press 'R' to renew the DHCP lease(s) or press any other key to return to the menu.\n");

  EFI_INPUT_KEY Key;
  Status = WaitForKeyPress(&Key);
  Print(L"\n");

  if (!EFI_ERROR(Status) && ((Key.UnicodeChar == L'R') || (Key.UnicodeChar == L'r'))) {
    RenewDhcpLeases(HandleBuffer, HandleCount);

    Print(L"Updated networking information:\n\n");
    for (UINTN Index = 0; Index < HandleCount; Index++) {
      DisplayDhcpInterfaceInformation(HandleBuffer[Index], Index);
    }

    Print(L"Press any key to return to the menu...\n");
    WaitForKeyPress(NULL);
  }

Cleanup:
  FreeDhcpHandleBuffer(HandleBuffer);
}

STATIC
VOID
FreeHttpHeaders(
  IN EFI_HTTP_HEADER *Headers,
  IN UINTN            HeaderCount
  )
{
  if ((Headers == NULL) || (HeaderCount == 0)) {
    return;
  }

  for (UINTN Index = 0; Index < HeaderCount; Index++) {
    if (Headers[Index].FieldName != NULL) {
      FreePool(Headers[Index].FieldName);
    }
    if (Headers[Index].FieldValue != NULL) {
      FreePool(Headers[Index].FieldValue);
    }
  }

  FreePool(Headers);
}

STATIC
VOID
ShowJsonPayload(
  IN CONST CHAR8 *JsonPayload
  )
{
  Print(L"JSON Payload\n");
  Print(L"------------\n\n");

  if ((JsonPayload == NULL) || (JsonPayload[0] == '\0')) {
    Print(L"No JSON payload is available.\n\n");
  } else {
    Print(L"%a\n\n", JsonPayload);
  }

  Print(L"Press any key to return to the menu...\n");
  WaitForKeyPress(NULL);
}

STATIC
EFI_STATUS
PromptForServerUrl(
  OUT CHAR16 **ServerUrl
  )
{
  if (ServerUrl == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *ServerUrl = NULL;

  if ((gST == NULL) || (gST->ConIn == NULL)) {
    return EFI_UNSUPPORTED;
  }

  Print(L"DHCP did not provide a server URL.\n");
  Print(L"Enter the server URL manually and press Enter (or press ESC to cancel).\n");
  Print(L"> ");

  CHAR16     Buffer[SERVER_URL_MAX_LENGTH];
  EFI_STATUS Status;
  UINTN      Length = 0;

  ZeroMem(Buffer, sizeof(Buffer));

  while (TRUE) {
    EFI_INPUT_KEY Key;
    Status = WaitForKeyPress(&Key);
    if (EFI_ERROR(Status)) {
      Print(L"\nUnable to read user input: %r\n", Status);
      mWaitForKeyPressSupported = FALSE;
      return Status;
    }

    if ((Key.UnicodeChar == CHAR_CARRIAGE_RETURN) || (Key.UnicodeChar == CHAR_LINEFEED)) {
      Print(L"\n");
      break;
    }

    if (Key.UnicodeChar == CHAR_BACKSPACE) {
      if (Length > 0) {
        Length--;
        Buffer[Length] = L'\0';
        Print(L"\b \b");
      }
      continue;
    }

    if ((Key.UnicodeChar == 0) && (Key.ScanCode == SCAN_ESC)) {
      Print(L"\n");
      return EFI_ABORTED;
    }

    if ((Key.UnicodeChar < L' ') && (Key.UnicodeChar != 0)) {
      continue;
    }

    if (Length >= (SERVER_URL_MAX_LENGTH - 1)) {
      Print(L"\a");
      continue;
    }

    Buffer[Length++] = Key.UnicodeChar;
    Print(L"%c", Key.UnicodeChar);
  }

  if (Length == 0) {
    return EFI_ABORTED;
  }

  CHAR16 *Allocated = AllocateZeroPool((Length + 1) * sizeof(CHAR16));
  if (Allocated == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem(Allocated, Buffer, Length * sizeof(CHAR16));
  Allocated[Length] = L'\0';

  *ServerUrl = Allocated;

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
ShouldIncludeDhcpClientHeaderForUrl(
  IN CONST CHAR16 *ServerUrl
  )
{
  if ((ServerUrl == NULL) || (ServerUrl[0] == L'\0')) {
    return FALSE;
  }

  CONST CHAR16 *HostStart = ServerUrl;
  CONST CHAR16 *SchemeSeparator = StrStr(ServerUrl, L"://");
  if (SchemeSeparator != NULL) {
    HostStart = SchemeSeparator + 3;
  }

  while (*HostStart == L'/') {
    HostStart++;
  }

  if (*HostStart == L'\0') {
    return FALSE;
  }

  CONST CHAR16 *HostEnd = HostStart;
  while ((*HostEnd != L'\0') && (*HostEnd != L'/') && (*HostEnd != L':')) {
    HostEnd++;
  }

  UINTN HostLength = (UINTN)(HostEnd - HostStart);
  if (HostLength == 0) {
    return FALSE;
  }

  CONST CHAR16 Target[]      = L"qr-reporter";
  CONST UINTN TargetLength   = ARRAY_SIZE(Target) - 1;

  if (HostLength < TargetLength) {
    return FALSE;
  }

  for (UINTN Index = 0; Index < TargetLength; Index++) {
    CHAR16 Current = HostStart[Index];
    if ((Current >= L'A') && (Current <= L'Z')) {
      Current = (CHAR16)(Current - L'A' + L'a');
    }

    if (Current != Target[Index]) {
      return FALSE;
    }
  }

  if (HostLength == TargetLength) {
    return TRUE;
  }

  CHAR16 NextCharacter = HostStart[TargetLength];
  if (NextCharacter == L'.') {
    return TRUE;
  }

  return FALSE;
}

STATIC
EFI_STATUS
SendHttpPostRequest(
  IN EFI_HTTP_PROTOCOL *Http,
  IN CONST CHAR16      *ServerUrl,
  IN CONST CHAR8       *Payload,
  IN UINTN              PayloadLength,
  IN BOOLEAN            IncludeDhcpClientHeader,
  IN CONST CHAR16      *PayloadDescription
  )
{
  if ((Http == NULL) || (ServerUrl == NULL) || (Payload == NULL) ||
      (PayloadLength == 0) || (PayloadDescription == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  CHAR8 ContentTypeName[]   = "Content-Type";
  CHAR8 ContentTypeValue[]  = "application/json";
  CHAR8 ContentLengthName[] = "Content-Length";
  CHAR8 ContentLengthValue[32];
  AsciiSPrint(ContentLengthValue, sizeof(ContentLengthValue), "%Lu", (UINT64)PayloadLength);

  CHAR8 DhcpClientName[]  = "dhcp-client";
  CHAR8 DhcpClientValue[] = "1";

  EFI_HTTP_HEADER RequestHeaders[3];
  UINTN           HeaderCount = 0;

  RequestHeaders[HeaderCount].FieldName  = ContentTypeName;
  RequestHeaders[HeaderCount].FieldValue = ContentTypeValue;
  HeaderCount++;

  RequestHeaders[HeaderCount].FieldName  = ContentLengthName;
  RequestHeaders[HeaderCount].FieldValue = ContentLengthValue;
  HeaderCount++;

  if (IncludeDhcpClientHeader) {
    RequestHeaders[HeaderCount].FieldName  = DhcpClientName;
    RequestHeaders[HeaderCount].FieldValue = DhcpClientValue;
    HeaderCount++;
  }

  EFI_HTTP_REQUEST_DATA RequestData;
  ZeroMem(&RequestData, sizeof(RequestData));
  RequestData.Method = HttpMethodPost;
  RequestData.Url    = (CHAR16 *)ServerUrl;

  EFI_HTTP_MESSAGE RequestMessage;
  ZeroMem(&RequestMessage, sizeof(RequestMessage));
  RequestMessage.Data.Request = &RequestData;
  RequestMessage.HeaderCount  = HeaderCount;
  RequestMessage.Headers      = RequestHeaders;
  RequestMessage.BodyLength   = PayloadLength;
  RequestMessage.Body         = (VOID *)Payload;

  EFI_HTTP_TOKEN RequestToken;
  ZeroMem(&RequestToken, sizeof(RequestToken));
  RequestToken.Message = &RequestMessage;

  EFI_STATUS Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, NULL, NULL, &RequestToken.Event);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = Http->Request(Http, &RequestToken);
  if (!EFI_ERROR(Status)) {
    UINTN EventIndex;
    Status = gBS->WaitForEvent(1, &RequestToken.Event, &EventIndex);
    if (!EFI_ERROR(Status)) {
      Status = RequestToken.Status;
    }
  }

  gBS->CloseEvent(RequestToken.Event);
  RequestToken.Event = NULL;

  if (EFI_ERROR(Status)) {
    Print(L"HTTP request for %s failed: %r\n", PayloadDescription, Status);
    return Status;
  }

  EFI_HTTP_RESPONSE_DATA ResponseData;
  EFI_HTTP_MESSAGE      ResponseMessage;
  EFI_HTTP_TOKEN        ResponseToken;

  ZeroMem(&ResponseData, sizeof(ResponseData));
  ZeroMem(&ResponseMessage, sizeof(ResponseMessage));
  ZeroMem(&ResponseToken, sizeof(ResponseToken));

  ResponseMessage.Data.Response = &ResponseData;
  ResponseToken.Message         = &ResponseMessage;

  EFI_STATUS ResponseStatus = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, NULL, NULL, &ResponseToken.Event);
  if (EFI_ERROR(ResponseStatus)) {
    return ResponseStatus;
  }

  ResponseStatus = Http->Response(Http, &ResponseToken);
  if (!EFI_ERROR(ResponseStatus)) {
    UINTN EventIndex;
    ResponseStatus = gBS->WaitForEvent(1, &ResponseToken.Event, &EventIndex);
    if (!EFI_ERROR(ResponseStatus)) {
      ResponseStatus = ResponseToken.Status;
    }
  }

  gBS->CloseEvent(ResponseToken.Event);
  ResponseToken.Event = NULL;

  Status = ResponseStatus;

  if (EFI_ERROR(Status) && (Status != EFI_HTTP_ERROR)) {
    Print(L"HTTP response for %s failed: %r\n", PayloadDescription, Status);
    FreeHttpHeaders(ResponseMessage.Headers, ResponseMessage.HeaderCount);
    return Status;
  }

  EFI_HTTP_STATUS_CODE HttpStatus = ResponseData.StatusCode;

  if (Status == EFI_HTTP_ERROR) {
    Print(L"Server returned HTTP error %u for %s\n", (UINT32)HttpStatus, PayloadDescription);
    FreeHttpHeaders(ResponseMessage.Headers, ResponseMessage.HeaderCount);
    return EFI_PROTOCOL_ERROR;
  }

  Print(L"Server returned HTTP status %u for %s\n", (UINT32)HttpStatus, PayloadDescription);

  EFI_STATUS FinalStatus;
  if ((HttpStatus >= HTTP_STATUS_200_OK) && (HttpStatus < HTTP_STATUS_300_MULTIPLE_CHOICES)) {
    FinalStatus = EFI_SUCCESS;
  } else {
    FinalStatus = EFI_PROTOCOL_ERROR;
  }

  FreeHttpHeaders(ResponseMessage.Headers, ResponseMessage.HeaderCount);
  return FinalStatus;
}

STATIC
EFI_STATUS
PostSystemInfoToServer(
  IN CONST CHAR8 *JsonPayload,
  IN UINTN        PayloadLength
  )
{
  if ((JsonPayload == NULL) || (PayloadLength == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  CHAR16     *ServerUrl = NULL;
  EFI_STATUS  Status    = GetServerUrlFromDhcp(&ServerUrl);
  if (EFI_ERROR(Status) || (ServerUrl == NULL) || (ServerUrl[0] == L'\0')) {
    if (Status == EFI_NOT_FOUND) {
      Print(L"DHCP server URL option was not provided.\n");
    } else if (EFI_ERROR(Status)) {
      Print(L"Unable to retrieve server URL from DHCP: %r\n", Status);
    } else {
      Print(L"DHCP provided an empty server URL.\n");
    }

    if (ServerUrl != NULL) {
      FreePool(ServerUrl);
      ServerUrl = NULL;
    }

    EFI_STATUS PromptStatus = PromptForServerUrl(&ServerUrl);
    if (EFI_ERROR(PromptStatus)) {
      if (PromptStatus == EFI_ABORTED) {
        Print(L"Manual server URL entry canceled by user.\n");
      } else {
        Print(L"Unable to obtain server URL: %r\n", PromptStatus);
      }
      return PromptStatus;
    }
  }

  if ((ServerUrl == NULL) || (ServerUrl[0] == L'\0')) {
    Print(L"Server URL is empty.\n");
    if (ServerUrl != NULL) {
      FreePool(ServerUrl);
    }
    return EFI_NOT_FOUND;
  }

  Print(L"Using server URL: %s\n", ServerUrl);

  BOOLEAN IncludeDhcpHeader = ShouldIncludeDhcpClientHeaderForUrl(ServerUrl);

  CHAR8 *HardwarePayload       = NULL;
  UINTN  HardwarePayloadLength = 0;

  Status = BuildHardwareInventoryPayload(&HardwarePayload, &HardwarePayloadLength);
  if (EFI_ERROR(Status)) {
    Print(L"Unable to build hardware inventory payload: %r\n", Status);
    FreePool(ServerUrl);
    return Status;
  }

  EFI_HANDLE *HandleBuffer = NULL;
  UINTN       HandleCount  = 0;

  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiHttpServiceBindingProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status) || (HandleCount == 0) || (HandleBuffer == NULL)) {
    if (!EFI_ERROR(Status)) {
      Status = EFI_NOT_FOUND;
    }
    Print(L"Unable to locate HTTP service binding: %r\n", Status);
    if (HandleBuffer != NULL) {
      FreePool(HandleBuffer);
    }
    if (HardwarePayload != NULL) {
      FreePool(HardwarePayload);
    }
    FreePool(ServerUrl);
    return Status;
  }

  EFI_STATUS Result    = EFI_DEVICE_ERROR;
  BOOLEAN    Completed = FALSE;

  for (UINTN Index = 0; Index < HandleCount; Index++) {
    EFI_SERVICE_BINDING_PROTOCOL      *ServiceBinding = NULL;
    EFI_HANDLE                         ChildHandle    = NULL;
    EFI_HTTP_PROTOCOL                 *Http           = NULL;
    BOOLEAN                            ChildCreated   = FALSE;
    BOOLEAN                            HttpConfigured = FALSE;

    Status = gBS->HandleProtocol(
                    HandleBuffer[Index],
                    &gEfiHttpServiceBindingProtocolGuid,
                    (VOID **)&ServiceBinding
                    );
    if (EFI_ERROR(Status) || (ServiceBinding == NULL)) {
      continue;
    }

    Status = ServiceBinding->CreateChild(ServiceBinding, &ChildHandle);
    if (EFI_ERROR(Status) || (ChildHandle == NULL)) {
      continue;
    }
    ChildCreated = TRUE;

    Status = gBS->HandleProtocol(ChildHandle, &gEfiHttpProtocolGuid, (VOID **)&Http);
    if (EFI_ERROR(Status) || (Http == NULL)) {
      goto NextHandle;
    }

    EFI_HTTPv4_ACCESS_POINT AccessPoint;
    ZeroMem(&AccessPoint, sizeof(AccessPoint));
    AccessPoint.UseDefaultAddress = TRUE;
    AccessPoint.LocalPort         = 0;

    EFI_HTTP_CONFIG_DATA ConfigData;
    ZeroMem(&ConfigData, sizeof(ConfigData));
    ConfigData.HttpVersion        = HttpVersion11;
    ConfigData.TimeOutMillisec    = 0;
    ConfigData.LocalAddressIsIPv6 = FALSE;
    ConfigData.AccessPoint.IPv4Node = &AccessPoint;

    Status = Http->Configure(Http, &ConfigData);
    if (EFI_ERROR(Status)) {
      goto NextHandle;
    }
    HttpConfigured = TRUE;

    Status = SendHttpPostRequest(
               Http,
               ServerUrl,
               JsonPayload,
               PayloadLength,
               IncludeDhcpHeader,
               L"system information payload"
               );
    if (EFI_ERROR(Status)) {
      Result = Status;
      goto NextHandle;
    }

    if ((HardwarePayload != NULL) && (HardwarePayloadLength > 0)) {
      Status = SendHttpPostRequest(
                 Http,
                 ServerUrl,
                 HardwarePayload,
                 HardwarePayloadLength,
                 IncludeDhcpHeader,
                 L"hardware inventory payload"
                 );
      if (EFI_ERROR(Status)) {
        Result = Status;
        goto NextHandle;
      }
    }

    Result    = EFI_SUCCESS;
    Completed = TRUE;

NextHandle:
    if (HttpConfigured && (Http != NULL)) {
      Http->Configure(Http, NULL);
    }

    if (ChildCreated && (ServiceBinding != NULL) && (ChildHandle != NULL)) {
      ServiceBinding->DestroyChild(ServiceBinding, ChildHandle);
    }

    if (Completed) {
      break;
    }
  }

  if (!Completed && (Result == EFI_DEVICE_ERROR)) {
    Print(L"Unable to send HTTP request using available handles.\n");
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }

  if (HardwarePayload != NULL) {
    FreePool(HardwarePayload);
  }

  FreePool(ServerUrl);

  return Result;
}

STATIC
VOID
RenderQuietRow(
  IN UINTN TotalModules
  )
{
  UINTN Characters = TotalModules * 2;
  CHAR16 RowBuffer[(COMPUTER_INFO_QR_MAX_SIZE + (QUIET_ZONE_SIZE * 2)) * 2 + 1];

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
  CHAR16 RowBuffer[(COMPUTER_INFO_QR_MAX_SIZE + (QUIET_ZONE_SIZE * 2)) * 2 + 1];
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
BOOLEAN
RenderQrToFramebuffer(
  IN CONST COMPUTER_INFO_QR_CODE *QrCode
  )
{
  if ((QrCode == NULL) || (QrCode->Size == 0)) {
    return FALSE;
  }

  if (gBS == NULL) {
    return FALSE;
  }

  EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
  EFI_STATUS                    Status;

  Status = gBS->LocateProtocol(
                  &gEfiGraphicsOutputProtocolGuid,
                  NULL,
                  (VOID **)&GraphicsOutput
                  );
  if (EFI_ERROR(Status) || (GraphicsOutput == NULL)) {
    return FALSE;
  }

  if ((GraphicsOutput->Mode == NULL) || (GraphicsOutput->Mode->Info == NULL)) {
    return FALSE;
  }

  CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *ModeInfo = GraphicsOutput->Mode->Info;
  UINTN                                      HorizontalResolution = ModeInfo->HorizontalResolution;
  UINTN                                      VerticalResolution   = ModeInfo->VerticalResolution;

  if ((HorizontalResolution == 0) || (VerticalResolution == 0)) {
    return FALSE;
  }

  UINTN TotalModules = QrCode->Size + (QUIET_ZONE_SIZE * 2);
  if (TotalModules == 0) {
    return FALSE;
  }

  UINTN ModulePixelSize = HorizontalResolution / TotalModules;
  UINTN VerticalModuleSize = VerticalResolution / TotalModules;
  if (VerticalModuleSize < ModulePixelSize) {
    ModulePixelSize = VerticalModuleSize;
  }

  if (ModulePixelSize == 0) {
    return FALSE;
  }

  UINTN QrPixelSize = ModulePixelSize * TotalModules;
  UINTN OffsetX = 0;
  UINTN OffsetY = 0;

  if (HorizontalResolution > QrPixelSize) {
    OffsetX = (HorizontalResolution - QrPixelSize) / 2;
  }
  if (VerticalResolution > QrPixelSize) {
    OffsetY = (VerticalResolution - QrPixelSize) / 2;
  }

  EFI_GRAPHICS_OUTPUT_BLT_PIXEL White = { 0xFF, 0xFF, 0xFF, 0x00 };
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL Black = { 0x00, 0x00, 0x00, 0x00 };

  Status = GraphicsOutput->Blt(
                               GraphicsOutput,
                               &White,
                               EfiBltVideoFill,
                               0,
                               0,
                               0,
                               0,
                               HorizontalResolution,
                               VerticalResolution,
                               0
                               );
  if (EFI_ERROR(Status)) {
    return FALSE;
  }

  for (UINTN Row = 0; Row < QrCode->Size; Row++) {
    for (UINTN Column = 0; Column < QrCode->Size; Column++) {
      if (QrCode->Modules[Row][Column] == 0) {
        continue;
      }

      UINTN PixelX = OffsetX + (Column + QUIET_ZONE_SIZE) * ModulePixelSize;
      UINTN PixelY = OffsetY + (Row + QUIET_ZONE_SIZE) * ModulePixelSize;

      Status = GraphicsOutput->Blt(
                                     GraphicsOutput,
                                     &Black,
                                     EfiBltVideoFill,
                                     0,
                                     0,
                                     PixelX,
                                     PixelY,
                                     ModulePixelSize,
                                     ModulePixelSize,
                                     0
                                     );
      if (EFI_ERROR(Status)) {
        return FALSE;
      }
    }
  }

  return TRUE;
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
  if (RenderQrToFramebuffer(QrCode)) {
    return;
  }

  if (gST->ConOut != NULL) {
    gST->ConOut->ClearScreen(gST->ConOut);
  }

  RenderQrCode(QrCode);
}

STATIC
EFI_STATUS
GetMenuSelection(
  OUT CHAR16 *Selection
  )
{
  if (Selection == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  while (TRUE) {
    Print(L"Computer Information Utility\n");
    Print(L"============================\n");
    Print(L"1. Display QR code\n");
    Print(L"2. Send system information to server\n");
    Print(L"3. Display networking information\n");
    Print(L"4. Display JSON payload\n");
    Print(L"5. Renew DHCP lease(s)\n");
    Print(L"Q. Quit\n\n");
    Print(L"Select an option: ");

    EFI_INPUT_KEY Key;
    EFI_STATUS    Status = WaitForKeyPress(&Key);
    Print(L"\n");
    if (EFI_ERROR(Status)) {
      return Status;
    }

    CHAR16 Value = Key.UnicodeChar;
    if ((Value == L'1') || (Value == L'2') || (Value == L'3') || (Value == L'4') ||
        (Value == L'5') || (Value == L'Q') || (Value == L'q')) {
      *Selection = Value;
      return EFI_SUCCESS;
    }

    Print(L"Invalid selection. Please try again.\n\n");
  }
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

  CHAR8 CpuModel[HARDWARE_MODEL_BUFFER_LENGTH];
  CHAR8 CpuSize[HARDWARE_SIZE_BUFFER_LENGTH];
  CHAR8 BoardModel[HARDWARE_MODEL_BUFFER_LENGTH];
  CHAR8 BoardSize[HARDWARE_SIZE_BUFFER_LENGTH];
  CHAR8 MemoryModel[HARDWARE_MODEL_BUFFER_LENGTH];
  CHAR8 MemorySize[HARDWARE_SIZE_BUFFER_LENGTH];

  GetCpuInfo(CpuModel, sizeof(CpuModel), CpuSize, sizeof(CpuSize));
  GetBaseboardInfo(BoardModel, sizeof(BoardModel), BoardSize, sizeof(BoardSize));
  GetMemoryInfo(MemoryModel, sizeof(MemoryModel), MemorySize, sizeof(MemorySize));

  CHAR8 JsonPayload[JSON_PAYLOAD_BUFFER_LENGTH];
  EFI_STATUS Status = BuildJsonPayload(
                       JsonPayload,
                       sizeof(JsonPayload),
                       UuidString,
                       MacString,
                       SerialNumber,
                       CpuModel,
                       CpuSize,
                       BoardModel,
                       BoardSize,
                       MemoryModel,
                       MemorySize
                       );
  if (EFI_ERROR(Status)) {
    Print(L"Failed to build JSON payload: %r\n", Status);
    return Status;
  }

  UINTN JsonLength = AsciiStrLen(JsonPayload);
  if (JsonLength == 0) {
    Print(L"JSON payload is empty.\n");
    return EFI_DEVICE_ERROR;
  }

  if (JsonLength > COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH) {
    Print(L"JSON payload is too large for the selected QR code size.\n");
    return EFI_BAD_BUFFER_SIZE;
  }

  COMPUTER_INFO_QR_CODE QrCode;
  Status = GenerateComputerInfoQrCode((CONST UINT8 *)JsonPayload, JsonLength, &QrCode);
  if (EFI_ERROR(Status)) {
    Print(L"QR code generation failed: %r\n", Status);
    return Status;
  }

  EFI_STATUS ReturnStatus   = EFI_SUCCESS;
  BOOLEAN    ExitRequested  = FALSE;

  while (!ExitRequested) {
    if ((gST != NULL) && (gST->ConOut != NULL)) {
      gST->ConOut->ClearScreen(gST->ConOut);
    }

    CHAR16 Selection;
    Status = GetMenuSelection(&Selection);
    if (EFI_ERROR(Status)) {
      ReturnStatus = Status;
      break;
    }

    switch (Selection) {
      case L'1':
        ShowQrScreen(&QrCode);
        WaitForKeyPress(NULL);
        break;

      case L'2':
        Print(L"Sending system information to the server...\n\n");
        Status = PostSystemInfoToServer(JsonPayload, JsonLength);
        if (EFI_ERROR(Status)) {
          Print(L"\nFailed to send system information: %r\n", Status);
        } else {
          Print(L"\nSystem information successfully sent.\n");
        }
        Print(L"\nPress any key to return to the menu...\n");
        WaitForKeyPress(NULL);
        break;

      case L'3':
        ShowNetworkInformation();
        break;

      case L'4':
        ShowJsonPayload(JsonPayload);
        break;

      case L'5':
        RenewDhcpLeasesFromMenu();
        break;

      case L'Q':
      case L'q':
        ExitRequested = TRUE;
        break;

      default:
        break;
    }
  }

  if ((gST != NULL) && (gST->ConOut != NULL)) {
    gST->ConOut->ClearScreen(gST->ConOut);
  }

  return ReturnStatus;
}

typedef struct {
  CHAR8   *Model;
  UINTN    ModelSize;
  CHAR8   *Size;
  UINTN    SizeSize;
  BOOLEAN  ModelFound;
  BOOLEAN  SizeFound;
} CPU_INFO_CONTEXT;

STATIC
VOID
UpdateCpuInfoFromRecord(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT CPU_INFO_CONTEXT   *Context
  )
{
  if ((Record == NULL) || (Context == NULL) || (Record->Type != SMBIOS_TYPE_PROCESSOR_INFORMATION)) {
    return;
  }

  CONST SMBIOS_TABLE_TYPE4 *Type4 = (CONST SMBIOS_TABLE_TYPE4 *)Record;

  if ((Context->Model != NULL) && !Context->ModelFound) {
    if ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE4, ProcessorVersion) + sizeof(Type4->ProcessorVersion))) {
      SMBIOS_TABLE_STRING StringNumber = Type4->ProcessorVersion;
      if (StringNumber != 0) {
        CHAR8 Temp[HARDWARE_MODEL_BUFFER_LENGTH];
        ZeroMem(Temp, sizeof(Temp));
        CopySmbiosString(Temp, sizeof(Temp), Record, StringNumber);
        NormalizeAsciiString(Temp);
        if (Temp[0] != '\0') {
          AsciiStrCpyS(Context->Model, Context->ModelSize, Temp);
          Context->ModelFound = TRUE;
        }
      }
    }
  }

  if ((Context->Size != NULL) && !Context->SizeFound) {
    UINT16 CoreCount = 0;

    if ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE4, CoreCount2) + sizeof(Type4->CoreCount2))) {
      if (Type4->CoreCount2 != 0) {
        CoreCount = Type4->CoreCount2;
      }
    }

    if (CoreCount == 0) {
      if ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE4, CoreCount) + sizeof(Type4->CoreCount))) {
        UINT8 CoreCount8 = Type4->CoreCount;
        if ((CoreCount8 != 0) && (CoreCount8 != 0xFF)) {
          CoreCount = CoreCount8;
        }
      }
    }

    if (CoreCount > 0) {
      AsciiSPrint(Context->Size, Context->SizeSize, "%u cores", CoreCount);
      Context->SizeFound = TRUE;
    } else {
      UINT16 Speed = 0;

      if ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE4, CurrentSpeed) + sizeof(Type4->CurrentSpeed))) {
        Speed = Type4->CurrentSpeed;
      }

      if ((Speed == 0) && ((UINTN)Record->Length >= (OFFSET_OF(SMBIOS_TABLE_TYPE4, MaxSpeed) + sizeof(Type4->MaxSpeed)))) {
        Speed = Type4->MaxSpeed;
      }

      if (Speed > 0) {
        AsciiSPrint(Context->Size, Context->SizeSize, "%u MHz", Speed);
        Context->SizeFound = TRUE;
      }
    }
  }
}

STATIC
BOOLEAN
CpuInfoVisitor(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT VOID               *Context
  )
{
  CPU_INFO_CONTEXT *CpuContext = (CPU_INFO_CONTEXT *)Context;

  UpdateCpuInfoFromRecord(Record, CpuContext);

  if (((CpuContext->Model == NULL) || CpuContext->ModelFound) &&
      ((CpuContext->Size == NULL) || CpuContext->SizeFound)) {
    return FALSE;
  }

  return TRUE;
}

STATIC
VOID
GetCpuInfo(
  OUT CHAR8 *CpuModel,
  IN UINTN  CpuModelSize,
  OUT CHAR8 *CpuSize,
  IN UINTN  CpuSizeSize
  )
{
  BOOLEAN NeedModel = (CpuModel != NULL) && (CpuModelSize > 0);
  BOOLEAN NeedSize  = (CpuSize != NULL) && (CpuSizeSize > 0);

  if (NeedModel) {
    CpuModel[0] = '\0';
  }

  if (NeedSize) {
    CpuSize[0] = '\0';
  }

  if (!NeedModel && !NeedSize) {
    return;
  }

  CPU_INFO_CONTEXT Context;
  ZeroMem(&Context, sizeof(Context));
  Context.Model     = NeedModel ? CpuModel : NULL;
  Context.ModelSize = CpuModelSize;
  Context.Size      = NeedSize ? CpuSize : NULL;
  Context.SizeSize  = CpuSizeSize;

  EFI_SMBIOS_PROTOCOL *Smbios = NULL;
  EFI_STATUS           Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (!EFI_ERROR(Status) && (Smbios != NULL)) {
    EFI_SMBIOS_HANDLE       Handle = SMBIOS_HANDLE_PI_RESERVED;
    EFI_SMBIOS_TABLE_HEADER *Record;

    while (TRUE) {
      Status = Smbios->GetNext(Smbios, &Handle, NULL, &Record, NULL);
      if (EFI_ERROR(Status)) {
        break;
      }

      if (Record == NULL) {
        continue;
      }

      UpdateCpuInfoFromRecord((CONST SMBIOS_STRUCTURE *)Record, &Context);

      if (((!NeedModel) || Context.ModelFound) && ((!NeedSize) || Context.SizeFound)) {
        break;
      }
    }
  }

  if ((NeedModel && !Context.ModelFound) || (NeedSize && !Context.SizeFound)) {
    CONST UINT8 *RawTable  = NULL;
    UINTN        RawLength = 0;

    Status = GetSmbiosRawTable(&RawTable, &RawLength);
    if (!EFI_ERROR(Status) && (RawTable != NULL) && (RawLength != 0)) {
      EnumerateRawSmbiosTable(RawTable, RawLength, CpuInfoVisitor, &Context);
    }
  }

  if (NeedModel && (!Context.ModelFound || (CpuModel[0] == '\0'))) {
    AsciiStrCpyS(CpuModel, CpuModelSize, UNKNOWN_STRING);
  }

  if (NeedSize && (!Context.SizeFound || (CpuSize[0] == '\0'))) {
    AsciiStrCpyS(CpuSize, CpuSizeSize, UNKNOWN_STRING);
  }
}

STATIC
CONST CHAR8 *
GetBaseboardTypeDescription(
  IN UINT8 BoardType
  )
{
  switch (BoardType) {
    case BaseBoardTypeOther:
      return "Other";
    case BaseBoardTypeUnknown:
      return "Unknown";
    case BaseBoardTypeServerBlade:
      return "Server Blade";
    case BaseBoardTypeConnectivitySwitch:
      return "Connectivity Switch";
    case BaseBoardTypeSystemManagementModule:
      return "System Management Module";
    case BaseBoardTypeProcessorModule:
      return "Processor Module";
    case BaseBoardTypeIOModule:
      return "I/O Module";
    case BaseBoardTypeMemoryModule:
      return "Memory Module";
    case BaseBoardTypeDaughterBoard:
      return "Daughter Board";
    case BaseBoardTypeMotherBoard:
      return "Motherboard";
    case BaseBoardTypeProcessorMemoryModule:
      return "Processor/Memory Module";
    case BaseBoardTypeProcessorIOModule:
      return "Processor/I/O Module";
    case BaseBoardTypeInterconnectBoard:
      return "Interconnect Board";
    default:
      return NULL;
  }
}

typedef struct {
  CHAR8   *Model;
  UINTN    ModelSize;
  CHAR8   *Size;
  UINTN    SizeSize;
  BOOLEAN  ModelFound;
  BOOLEAN  SizeFound;
} BASEBOARD_INFO_CONTEXT;

STATIC
VOID
UpdateBaseboardInfoFromRecord(
  IN CONST SMBIOS_STRUCTURE      *Record,
  IN OUT BASEBOARD_INFO_CONTEXT  *Context
  )
{
  if ((Record == NULL) || (Context == NULL) || (Record->Type != SMBIOS_TYPE_BASEBOARD_INFORMATION)) {
    return;
  }

  CONST SMBIOS_TABLE_TYPE2 *Type2 = (CONST SMBIOS_TABLE_TYPE2 *)Record;

  if ((Context->Model != NULL) && !Context->ModelFound) {
    if ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE2, ProductName)) {
      SMBIOS_TABLE_STRING StringNumber = Type2->ProductName;
      if (StringNumber != 0) {
        CHAR8 Temp[HARDWARE_MODEL_BUFFER_LENGTH];
        ZeroMem(Temp, sizeof(Temp));
        CopySmbiosString(Temp, sizeof(Temp), Record, StringNumber);
        NormalizeAsciiString(Temp);
        if (Temp[0] != '\0') {
          AsciiStrCpyS(Context->Model, Context->ModelSize, Temp);
          Context->ModelFound = TRUE;
        }
      }
    }
  }

  if ((Context->Model != NULL) && !Context->ModelFound) {
    if ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE2, Version)) {
      SMBIOS_TABLE_STRING VersionNumber = Type2->Version;
      if (VersionNumber != 0) {
        CHAR8 Temp[HARDWARE_MODEL_BUFFER_LENGTH];
        ZeroMem(Temp, sizeof(Temp));
        CopySmbiosString(Temp, sizeof(Temp), Record, VersionNumber);
        NormalizeAsciiString(Temp);
        if (Temp[0] != '\0') {
          AsciiStrCpyS(Context->Model, Context->ModelSize, Temp);
          Context->ModelFound = TRUE;
        }
      }
    }
  }

  if ((Context->Size != NULL) && !Context->SizeFound) {
    CONST CHAR8 *Description = GetBaseboardTypeDescription(Type2->BoardType);
    if ((Description != NULL) && (Description[0] != '\0')) {
      AsciiStrCpyS(Context->Size, Context->SizeSize, Description);
      Context->SizeFound = TRUE;
    }
  }
}

STATIC
BOOLEAN
BaseboardInfoVisitor(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT VOID               *Context
  )
{
  BASEBOARD_INFO_CONTEXT *BoardContext = (BASEBOARD_INFO_CONTEXT *)Context;

  UpdateBaseboardInfoFromRecord(Record, BoardContext);

  if (((BoardContext->Model == NULL) || BoardContext->ModelFound) &&
      ((BoardContext->Size == NULL) || BoardContext->SizeFound)) {
    return FALSE;
  }

  return TRUE;
}

STATIC
VOID
GetBaseboardInfo(
  OUT CHAR8 *BoardModel,
  IN UINTN  BoardModelSize,
  OUT CHAR8 *BoardSize,
  IN UINTN  BoardSizeSize
  )
{
  BOOLEAN NeedModel = (BoardModel != NULL) && (BoardModelSize > 0);
  BOOLEAN NeedSize  = (BoardSize != NULL) && (BoardSizeSize > 0);

  if (NeedModel) {
    BoardModel[0] = '\0';
  }

  if (NeedSize) {
    BoardSize[0] = '\0';
  }

  if (!NeedModel && !NeedSize) {
    return;
  }

  BASEBOARD_INFO_CONTEXT Context;
  ZeroMem(&Context, sizeof(Context));
  Context.Model     = NeedModel ? BoardModel : NULL;
  Context.ModelSize = BoardModelSize;
  Context.Size      = NeedSize ? BoardSize : NULL;
  Context.SizeSize  = BoardSizeSize;

  EFI_SMBIOS_PROTOCOL *Smbios = NULL;
  EFI_STATUS           Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (!EFI_ERROR(Status) && (Smbios != NULL)) {
    EFI_SMBIOS_HANDLE       Handle = SMBIOS_HANDLE_PI_RESERVED;
    EFI_SMBIOS_TABLE_HEADER *Record;

    while (TRUE) {
      Status = Smbios->GetNext(Smbios, &Handle, NULL, &Record, NULL);
      if (EFI_ERROR(Status)) {
        break;
      }

      if (Record == NULL) {
        continue;
      }

      UpdateBaseboardInfoFromRecord((CONST SMBIOS_STRUCTURE *)Record, &Context);

      if (((!NeedModel) || Context.ModelFound) && ((!NeedSize) || Context.SizeFound)) {
        break;
      }
    }
  }

  if ((NeedModel && !Context.ModelFound) || (NeedSize && !Context.SizeFound)) {
    CONST UINT8 *RawTable  = NULL;
    UINTN        RawLength = 0;

    Status = GetSmbiosRawTable(&RawTable, &RawLength);
    if (!EFI_ERROR(Status) && (RawTable != NULL) && (RawLength != 0)) {
      EnumerateRawSmbiosTable(RawTable, RawLength, BaseboardInfoVisitor, &Context);
    }
  }

  if (NeedModel && ((BoardModel[0] == '\0') || !Context.ModelFound)) {
    AsciiStrCpyS(BoardModel, BoardModelSize, UNKNOWN_STRING);
  }

  if (NeedSize && ((BoardSize[0] == '\0') || !Context.SizeFound)) {
    AsciiStrCpyS(BoardSize, BoardSizeSize, UNKNOWN_STRING);
  }
}

STATIC
CONST CHAR8 *
GetMemoryTypeDescription(
  IN UINT8 MemoryType
  )
{
  switch (MemoryType) {
    case MemoryTypeOther:
      return "Other";
    case MemoryTypeUnknown:
      return "Unknown";
    case MemoryTypeDram:
      return "DRAM";
    case MemoryTypeEdram:
      return "EDRAM";
    case MemoryTypeVram:
      return "VRAM";
    case MemoryTypeSram:
      return "SRAM";
    case MemoryTypeRam:
      return "RAM";
    case MemoryTypeRom:
      return "ROM";
    case MemoryTypeFlash:
      return "Flash";
    case MemoryTypeEeprom:
      return "EEPROM";
    case MemoryTypeFeprom:
      return "FEPROM";
    case MemoryTypeEprom:
      return "EPROM";
    case MemoryTypeCdram:
      return "CDRAM";
    case MemoryType3Dram:
      return "3DRAM";
    case MemoryTypeSdram:
      return "SDRAM";
    case MemoryTypeSgram:
      return "SGRAM";
    case MemoryTypeRdram:
      return "RDRAM";
    case MemoryTypeDdr:
      return "DDR";
    case MemoryTypeDdr2:
      return "DDR2";
    case MemoryTypeDdr2FbDimm:
      return "DDR2 FB-DIMM";
    case MemoryTypeDdr3:
      return "DDR3";
    case MemoryTypeFbd2:
      return "FBD2";
    case MemoryTypeDdr4:
      return "DDR4";
    case MemoryTypeDdr5:
      return "DDR5";
    case MemoryTypeLpddr:
      return "LPDDR";
    case MemoryTypeLpddr2:
      return "LPDDR2";
    case MemoryTypeLpddr3:
      return "LPDDR3";
    case MemoryTypeLpddr4:
      return "LPDDR4";
    case MemoryTypeLpddr5:
      return "LPDDR5";
    case MemoryTypeLogicalNonVolatileDevice:
      return "Logical Non-Volatile Device";
    case MemoryTypeHBM:
      return "HBM";
    case MemoryTypeHBM2:
      return "HBM2";
    default:
      return NULL;
  }
}

STATIC
UINT64
GetMemoryDeviceSizeInBytes(
  IN CONST SMBIOS_TABLE_TYPE17 *Type17,
  IN UINTN                      RecordLength
  )
{
  if (Type17 == NULL) {
    return 0;
  }

  if (RecordLength < (OFFSET_OF(SMBIOS_TABLE_TYPE17, Size) + sizeof(Type17->Size))) {
    return 0;
  }

  UINT16 SizeField = Type17->Size;

  if ((SizeField == 0) || (SizeField == 0xFFFF)) {
    return 0;
  }

  if (SizeField == 0x7FFF) {
    if (RecordLength < (OFFSET_OF(SMBIOS_TABLE_TYPE17, ExtendedSize) + sizeof(Type17->ExtendedSize))) {
      return 0;
    }

    UINT32 ExtendedSizeMb = Type17->ExtendedSize;
    if (ExtendedSizeMb == 0) {
      return 0;
    }

    return (UINT64)ExtendedSizeMb * 1024ULL * 1024ULL;
  }

  if ((SizeField & 0x8000) != 0) {
    UINT16 Kilobytes = SizeField & 0x7FFF;
    if (Kilobytes == 0) {
      return 0;
    }

    return (UINT64)Kilobytes * 1024ULL;
  }

  return (UINT64)SizeField * 1024ULL * 1024ULL;
}

typedef struct {
  CHAR8   *Model;
  UINTN    ModelSize;
  CHAR8   *Size;
  UINTN    SizeSize;
  BOOLEAN  ModelFound;
  BOOLEAN  SizeFound;
  BOOLEAN  AnyDevicePresent;
  UINT64   TotalSizeBytes;
} MEMORY_INFO_CONTEXT;

STATIC
VOID
UpdateMemoryInfoFromRecord(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT MEMORY_INFO_CONTEXT *Context
  )
{
  if ((Record == NULL) || (Context == NULL) || (Record->Type != SMBIOS_TYPE_MEMORY_DEVICE)) {
    return;
  }

  Context->AnyDevicePresent = TRUE;

  CONST SMBIOS_TABLE_TYPE17 *Type17 = (CONST SMBIOS_TABLE_TYPE17 *)Record;

  UINT64 ModuleSizeBytes = GetMemoryDeviceSizeInBytes(Type17, Record->Length);
  if (ModuleSizeBytes > 0) {
    Context->TotalSizeBytes += ModuleSizeBytes;
  }

  if ((Context->Model != NULL) && !Context->ModelFound) {
    if ((UINTN)Record->Length > OFFSET_OF(SMBIOS_TABLE_TYPE17, PartNumber)) {
      SMBIOS_TABLE_STRING PartNumber = Type17->PartNumber;
      if (PartNumber != 0) {
        CHAR8 Temp[HARDWARE_MODEL_BUFFER_LENGTH];
        ZeroMem(Temp, sizeof(Temp));
        CopySmbiosString(Temp, sizeof(Temp), Record, PartNumber);
        NormalizeAsciiString(Temp);
        if (Temp[0] != '\0') {
          AsciiStrCpyS(Context->Model, Context->ModelSize, Temp);
          Context->ModelFound = TRUE;
        }
      }
    }
  }

  if ((Context->Model != NULL) && !Context->ModelFound) {
    CONST CHAR8 *Description = GetMemoryTypeDescription(Type17->MemoryType);
    if ((Description != NULL) && (Description[0] != '\0')) {
      AsciiStrCpyS(Context->Model, Context->ModelSize, Description);
      Context->ModelFound = TRUE;
    }
  }
}

STATIC
BOOLEAN
MemoryInfoVisitor(
  IN CONST SMBIOS_STRUCTURE *Record,
  IN OUT VOID               *Context
  )
{
  UpdateMemoryInfoFromRecord(Record, (MEMORY_INFO_CONTEXT *)Context);
  return TRUE;
}

STATIC
VOID
FormatSizeString(
  OUT CHAR8 *Buffer,
  IN UINTN   BufferSize,
  IN UINT64  SizeInBytes
  )
{
  if ((Buffer == NULL) || (BufferSize == 0)) {
    return;
  }

  if (SizeInBytes == 0) {
    Buffer[0] = '\0';
    return;
  }

  CONST UINT64 OneKilobyte = 1024ULL;
  CONST UINT64 OneMegabyte = OneKilobyte * 1024ULL;
  CONST UINT64 OneGigabyte = OneMegabyte * 1024ULL;

  if (SizeInBytes >= OneGigabyte) {
    UINT64 Gigabytes = SizeInBytes / OneGigabyte;
    UINT64 Remainder = SizeInBytes % OneGigabyte;
    if (Remainder == 0) {
      AsciiSPrint(Buffer, BufferSize, "%Lu GB", Gigabytes);
      return;
    }
  }

  if (SizeInBytes >= OneMegabyte) {
    UINT64 Megabytes = SizeInBytes / OneMegabyte;
    AsciiSPrint(Buffer, BufferSize, "%Lu MB", Megabytes);
    return;
  }

  UINT64 Kilobytes = SizeInBytes / OneKilobyte;
  if (Kilobytes == 0) {
    Kilobytes = 1;
  }

  AsciiSPrint(Buffer, BufferSize, "%Lu KB", Kilobytes);
}

STATIC
VOID
GetMemoryInfo(
  OUT CHAR8 *MemoryModel,
  IN UINTN  MemoryModelSize,
  OUT CHAR8 *MemorySize,
  IN UINTN  MemorySizeSize
  )
{
  BOOLEAN NeedModel = (MemoryModel != NULL) && (MemoryModelSize > 0);
  BOOLEAN NeedSize  = (MemorySize != NULL) && (MemorySizeSize > 0);

  if (NeedModel) {
    MemoryModel[0] = '\0';
  }

  if (NeedSize) {
    MemorySize[0] = '\0';
  }

  if (!NeedModel && !NeedSize) {
    return;
  }

  MEMORY_INFO_CONTEXT Context;
  ZeroMem(&Context, sizeof(Context));
  Context.Model     = NeedModel ? MemoryModel : NULL;
  Context.ModelSize = MemoryModelSize;
  Context.Size      = NeedSize ? MemorySize : NULL;
  Context.SizeSize  = MemorySizeSize;

  EFI_SMBIOS_PROTOCOL *Smbios = NULL;
  EFI_STATUS           Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (!EFI_ERROR(Status) && (Smbios != NULL)) {
    EFI_SMBIOS_HANDLE       Handle = SMBIOS_HANDLE_PI_RESERVED;
    EFI_SMBIOS_TABLE_HEADER *Record;

    while (TRUE) {
      Status = Smbios->GetNext(Smbios, &Handle, NULL, &Record, NULL);
      if (EFI_ERROR(Status)) {
        break;
      }

      if (Record == NULL) {
        continue;
      }

      UpdateMemoryInfoFromRecord((CONST SMBIOS_STRUCTURE *)Record, &Context);
    }
  }

  if (!Context.AnyDevicePresent) {
    CONST UINT8 *RawTable  = NULL;
    UINTN        RawLength = 0;

    Status = GetSmbiosRawTable(&RawTable, &RawLength);
    if (!EFI_ERROR(Status) && (RawTable != NULL) && (RawLength != 0)) {
      EnumerateRawSmbiosTable(RawTable, RawLength, MemoryInfoVisitor, &Context);
    }
  }

  if (NeedSize && (Context.TotalSizeBytes > 0)) {
    FormatSizeString(MemorySize, MemorySizeSize, Context.TotalSizeBytes);
    Context.SizeFound = TRUE;
  }

  if (NeedModel && ((MemoryModel[0] == '\0') || !Context.ModelFound)) {
    AsciiStrCpyS(MemoryModel, MemoryModelSize, UNKNOWN_STRING);
  }

  if (NeedSize && ((MemorySize[0] == '\0') || (Context.TotalSizeBytes == 0))) {
    AsciiStrCpyS(MemorySize, MemorySizeSize, UNKNOWN_STRING);
  }
}
