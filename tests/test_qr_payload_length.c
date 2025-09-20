#include "stubs/Uefi.h"
#include "stubs/Library/BaseMemoryLib.h"
#include "stubs/Library/BaseLib.h"
#include "stubs/Library/MemoryAllocationLib.h"

#include "../ComputerInfoQrPkg/Application/QrCode.c"

#include <stdio.h>

static UINTN
DetermineVersionForPayload(
  UINTN PayloadLength,
  UINTN *DataCapacity
  )
{
  for (UINTN Version = COMPUTER_INFO_QR_MIN_VERSION; Version <= COMPUTER_INFO_QR_MAX_VERSION; Version++) {
    UINTN Capacity = GetDataCodewordCapacity(Version);
    if (Capacity == 0) {
      continue;
    }

    UINTN CharCountBits = (Version <= 9) ? 8 : 16;
    if ((CharCountBits == 8) && (PayloadLength > 0xFF)) {
      continue;
    }

    if (PayloadLength <= Capacity) {
      if (DataCapacity != NULL) {
        *DataCapacity = Capacity;
      }
      return Version;
    }
  }

  if (DataCapacity != NULL) {
    *DataCapacity = 0;
  }
  return 0;
}

static int
TestBuildDataCodewordsUsesSixteenBitLength(void)
{
  const UINTN PayloadLength = 300;
  UINT8 Payload[PayloadLength];
  for (UINTN Index = 0; Index < PayloadLength; Index++) {
    Payload[Index] = (UINT8)(Index & 0xFF);
  }

  UINT8 Codewords[COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH];
  UINTN DataCapacity = 0;
  UINTN Version = DetermineVersionForPayload(PayloadLength, &DataCapacity);
  if ((Version == 0) || (DataCapacity == 0)) {
    fprintf(stderr, "Unable to determine QR version for payload length %zu\n", PayloadLength);
    return 1;
  }

  UINTN CharCountBits = (Version <= 9) ? 8 : 16;
  if (CharCountBits != 16) {
    fprintf(stderr, "Expected to use 16-bit length field for payload %zu but selected version %zu\n", PayloadLength, Version);
    return 1;
  }

  EFI_STATUS Status = BuildDataCodewords(Payload, PayloadLength, Codewords, DataCapacity, 8);
  if (Status != EFI_BAD_BUFFER_SIZE) {
    fprintf(stderr, "Expected 8-bit length field rejection, got %llu\n", (unsigned long long)Status);
    return 1;
  }

  Status = BuildDataCodewords(Payload, PayloadLength, Codewords, DataCapacity, CharCountBits);
  if (Status != EFI_SUCCESS) {
    fprintf(stderr, "Expected success for 16-bit length field, got %llu\n", (unsigned long long)Status);
    return 1;
  }

  UINT8 ExpectedByte0 = (UINT8)(0x40 | ((PayloadLength >> 12) & 0x0F));
  UINT8 ExpectedByte1 = (UINT8)((PayloadLength >> 4) & 0xFF);
  UINT8 ExpectedByte2High = (UINT8)((PayloadLength & 0x0F) << 4);

  if (Codewords[0] != ExpectedByte0) {
    fprintf(stderr, "Unexpected mode/length byte: got 0x%02X expected 0x%02X\n", Codewords[0], ExpectedByte0);
    return 1;
  }

  if (Codewords[1] != ExpectedByte1) {
    fprintf(stderr, "Unexpected high length byte: got 0x%02X expected 0x%02X\n", Codewords[1], ExpectedByte1);
    return 1;
  }

  if ((Codewords[2] & 0xF0) != ExpectedByte2High) {
    fprintf(stderr, "Unexpected low length nibble: got 0x%02X expected 0x%02X\n", Codewords[2] & 0xF0, ExpectedByte2High);
    return 1;
  }

  return 0;
}

static int
TestGenerateComputerInfoQrCodeSelectsCorrectVersion(void)
{
  const UINTN PayloadLength = 300;
  UINT8 Payload[PayloadLength];
  for (UINTN Index = 0; Index < PayloadLength; Index++) {
    Payload[Index] = (UINT8)(Index & 0xFF);
  }

  COMPUTER_INFO_QR_CODE QrCode;
  EFI_STATUS Status = GenerateComputerInfoQrCode(Payload, PayloadLength, &QrCode);
  if (Status != EFI_SUCCESS) {
    fprintf(stderr, "GenerateComputerInfoQrCode failed with %llu\n", (unsigned long long)Status);
    return 1;
  }

  UINTN DerivedVersion = (QrCode.Size - 17) / 4;
  if (DerivedVersion <= 9) {
    fprintf(stderr, "Expected QR version >= 10 for payload >255 bytes, got %zu\n", DerivedVersion);
    return 1;
  }

  return 0;
}

int
main(void)
{
  if (TestBuildDataCodewordsUsesSixteenBitLength() != 0) {
    return 1;
  }

  if (TestGenerateComputerInfoQrCodeSelectsCorrectVersion() != 0) {
    return 1;
  }

  return 0;
}
