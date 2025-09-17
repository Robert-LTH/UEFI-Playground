#include <Uefi.h>

#include <IndustryStandard/SmBios.h>
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
#include <Protocol/ServiceBinding.h>
#include <Protocol/Smbios.h>

#include "QrCode.h"

#define QUIET_ZONE_SIZE                 2
#define INFO_BUFFER_LENGTH              (COMPUTER_INFO_QR_MAX_DATA_LENGTH + 1)
#define JSON_PAYLOAD_BUFFER_LENGTH      512
#define UUID_STRING_LENGTH              36
#define UUID_STRING_BUFFER_LENGTH       (UUID_STRING_LENGTH + 1)
#define MAC_ADDRESS_MAX_BYTES           32
#define MAC_STRING_MAX_LENGTH           (MAC_ADDRESS_MAX_BYTES * 2)
#define MAC_STRING_BUFFER_LENGTH        (MAC_STRING_MAX_LENGTH + 1)
#define SERIAL_NUMBER_BUFFER_LENGTH     (COMPUTER_INFO_QR_MAX_DATA_LENGTH + 1)
#define UNKNOWN_STRING                  "UNKNOWN"
#define DHCP_OPTION_PAD                 0
#define DHCP_OPTION_END                 255
#define COMPUTER_INFO_QR_SERVER_URL_OPTION  224
#define DHCP_OPTION_MAX_LENGTH              255
#define IPV4_STRING_BUFFER_LENGTH           16

STATIC
EFI_STATUS
WaitForKeyPress(
  OUT EFI_INPUT_KEY *Key OPTIONAL
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
EFI_STATUS
BuildJsonPayload(
  OUT CHAR8       *JsonBuffer,
  IN  UINTN        JsonBufferSize,
  IN  CONST CHAR8 *UuidString,
  IN  CONST CHAR8 *MacString,
  IN  CONST CHAR8 *SerialNumber
  )
{
  if ((JsonBuffer == NULL) || (JsonBufferSize == 0) ||
      (UuidString == NULL) || (MacString == NULL) || (SerialNumber == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  UINTN UuidLength   = AsciiStrLen(UuidString);
  UINTN MacLength    = AsciiStrLen(MacString);
  UINTN SerialLength = AsciiStrLen(SerialNumber);
  UINTN RequiredLength = 39 + UuidLength + MacLength + SerialLength;

  if (RequiredLength >= JsonBufferSize) {
    return EFI_BUFFER_TOO_SMALL;
  }

  AsciiSPrint(
    JsonBuffer,
    JsonBufferSize,
    "{\"uuid\":\"%a\",\"mac\":\"%a\",\"serial_number\":\"%a\"}",
    UuidString,
    MacString,
    SerialNumber
    );

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

    Status = Dhcp4->GetModeData(Dhcp4, &ModeData);
    if (EFI_ERROR(Status) || (ModeData.ReplyPacket == NULL)) {
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
PrintDhcpOptions(
  IN CONST EFI_DHCP4_PACKET *Packet
  )
{
  if ((Packet == NULL) || (Packet->Length <= OFFSET_OF(EFI_DHCP4_PACKET, Dhcp4.Option))) {
    Print(L"    No DHCP options available.\n");
    return;
  }

  CONST UINT8 *Option = Packet->Dhcp4.Option;
  CONST UINT8 *End    = ((CONST UINT8 *)Packet) + Packet->Length;
  CHAR16       AsciiBuffer[DHCP_OPTION_MAX_LENGTH + 1];

  while (Option < End) {
    UINT8 OptionCode = *Option++;

    if (OptionCode == DHCP_OPTION_PAD) {
      Print(L"    Option 0 (Pad)\n");
      continue;
    }

    if (OptionCode == DHCP_OPTION_END) {
      Print(L"    Option 255 (End)\n");
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
  }
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

  Print(L"  State: %s (%u)\n", Dhcp4StateToString(ModeData.State), (UINT32)ModeData.State);

  UINTN                        MacAddressSize = 0;
  EFI_SIMPLE_NETWORK_PROTOCOL *Snp            = NULL;
  Status = gBS->HandleProtocol(
                      Handle,
                      &gEfiSimpleNetworkProtocolGuid,
                      (VOID **)&Snp
                      );
  if (!EFI_ERROR(Status) && (Snp != NULL) && (Snp->Mode != NULL)) {
    MacAddressSize = Snp->Mode->HwAddressSize;
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
  IN EFI_HANDLE Handle
  )
{
  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EFI_DHCP4_PROTOCOL *Dhcp4 = NULL;
  EFI_STATUS          Status;

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

  if (Dhcp4->RenewRebind == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = Dhcp4->RenewRebind(Dhcp4, FALSE);
  if (Status == EFI_NO_MAPPING) {
    Status = Dhcp4->RenewRebind(Dhcp4, TRUE);
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
    EFI_STATUS Status = RenewDhcpLeaseOnHandle(HandleBuffer[Index]);
    if (EFI_ERROR(Status)) {
      Print(L"  Interface %u: Failed to renew DHCP lease: %r\n", (UINT32)(Index + 1), Status);
    } else {
      Print(L"  Interface %u: DHCP lease renewal requested successfully.\n", (UINT32)(Index + 1));
    }
  }

  Print(L"\n");
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

  Status = gBS->LocateHandleBuffer(
                          ByProtocol,
                          &gEfiDhcp4ProtocolGuid,
                          NULL,
                          &HandleCount,
                          &HandleBuffer
                          );
  if (EFI_ERROR(Status) || (HandleBuffer == NULL) || (HandleCount == 0)) {
    if (EFI_ERROR(Status)) {
      Print(L"Unable to locate DHCPv4 handles: %r\n", Status);
    } else {
      Print(L"No DHCPv4 interfaces found.\n");
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
  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }
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
EFI_STATUS
PostSystemInfoToServer(
  IN CONST CHAR8 *JsonPayload,
  IN UINTN        PayloadLength
  )
{
  if ((JsonPayload == NULL) || (PayloadLength == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  CHAR16 *ServerUrl = NULL;
  EFI_STATUS Status = GetServerUrlFromDhcp(&ServerUrl);
  if (EFI_ERROR(Status)) {
    Print(L"Unable to retrieve server URL from DHCP: %r\n", Status);
    return Status;
  }

  Print(L"Using server URL: %s\n", ServerUrl);

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

    CHAR8 ContentTypeName[]   = "Content-Type";
    CHAR8 ContentTypeValue[]  = "application/json";
    CHAR8 ContentLengthName[] = "Content-Length";
    CHAR8 ContentLengthValue[32];
    AsciiSPrint(ContentLengthValue, sizeof(ContentLengthValue), "%Lu", (UINT64)PayloadLength);

    EFI_HTTP_HEADER RequestHeaders[2];
    RequestHeaders[0].FieldName  = ContentTypeName;
    RequestHeaders[0].FieldValue = ContentTypeValue;
    RequestHeaders[1].FieldName  = ContentLengthName;
    RequestHeaders[1].FieldValue = ContentLengthValue;

    EFI_HTTP_REQUEST_DATA RequestData;
    ZeroMem(&RequestData, sizeof(RequestData));
    RequestData.Method = HttpMethodPost;
    RequestData.Url    = ServerUrl;

    EFI_HTTP_MESSAGE RequestMessage;
    ZeroMem(&RequestMessage, sizeof(RequestMessage));
    RequestMessage.Data.Request = &RequestData;
    RequestMessage.HeaderCount  = ARRAY_SIZE(RequestHeaders);
    RequestMessage.Headers      = RequestHeaders;
    RequestMessage.BodyLength   = PayloadLength;
    RequestMessage.Body         = (VOID *)JsonPayload;

    EFI_HTTP_TOKEN RequestToken;
    ZeroMem(&RequestToken, sizeof(RequestToken));
    RequestToken.Message = &RequestMessage;

    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, NULL, NULL, &RequestToken.Event);
    if (EFI_ERROR(Status)) {
      Result = Status;
      goto NextHandle;
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
      Print(L"HTTP request failed: %r\n", Status);
      Result = Status;
      goto NextHandle;
    }

    EFI_HTTP_RESPONSE_DATA ResponseData;
    EFI_HTTP_MESSAGE      ResponseMessage;
    EFI_HTTP_TOKEN        ResponseToken;

    ZeroMem(&ResponseData, sizeof(ResponseData));
    ZeroMem(&ResponseMessage, sizeof(ResponseMessage));
    ZeroMem(&ResponseToken, sizeof(ResponseToken));

    ResponseMessage.Data.Response = &ResponseData;
    ResponseToken.Message         = &ResponseMessage;

    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, NULL, NULL, &ResponseToken.Event);
    if (EFI_ERROR(Status)) {
      Result = Status;
      goto NextHandle;
    }

    Status = Http->Response(Http, &ResponseToken);
    if (!EFI_ERROR(Status)) {
      UINTN EventIndex;
      Status = gBS->WaitForEvent(1, &ResponseToken.Event, &EventIndex);
      if (!EFI_ERROR(Status)) {
        Status = ResponseToken.Status;
      }
    }

    gBS->CloseEvent(ResponseToken.Event);
    ResponseToken.Event = NULL;

    if (EFI_ERROR(Status) && (Status != EFI_HTTP_ERROR)) {
      Print(L"HTTP response failed: %r\n", Status);
      FreeHttpHeaders(ResponseMessage.Headers, ResponseMessage.HeaderCount);
      Result = Status;
      goto NextHandle;
    }

    if (Status == EFI_HTTP_ERROR) {
      Print(L"Server returned HTTP error %u\n", (UINT32)ResponseData.StatusCode);
      Result    = EFI_PROTOCOL_ERROR;
      Completed = TRUE;
    } else {
      Print(L"Server returned HTTP status %u\n", (UINT32)ResponseData.StatusCode);
      if ((ResponseData.StatusCode >= HTTP_STATUS_200_OK) &&
          (ResponseData.StatusCode < HTTP_STATUS_300_MULTIPLE_CHOICES)) {
        Result    = EFI_SUCCESS;
      } else {
        Result    = EFI_PROTOCOL_ERROR;
      }
      Completed = TRUE;
    }

    FreeHttpHeaders(ResponseMessage.Headers, ResponseMessage.HeaderCount);

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
    Print(L"Q. Quit\n\n");
    Print(L"Select an option: ");

    EFI_INPUT_KEY Key;
    EFI_STATUS    Status = WaitForKeyPress(&Key);
    Print(L"\n");
    if (EFI_ERROR(Status)) {
      return Status;
    }

    CHAR16 Value = Key.UnicodeChar;
    if ((Value == L'1') || (Value == L'2') || (Value == L'3') || (Value == L'Q') || (Value == L'q')) {
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

  CHAR8 JsonPayload[JSON_PAYLOAD_BUFFER_LENGTH];
  Status = BuildJsonPayload(JsonPayload, sizeof(JsonPayload), UuidString, MacString, SerialNumber);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to build JSON payload: %r\n", Status);
    return Status;
  }

  UINTN JsonLength = AsciiStrLen(JsonPayload);
  if (JsonLength == 0) {
    Print(L"JSON payload is empty.\n");
    return EFI_DEVICE_ERROR;
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
        Print(L"\nPress any key to return to the menu...\n");
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
