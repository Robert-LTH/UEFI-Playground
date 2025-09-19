#include "QrCode.h"

#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>

#define GF_SIZE                       256
#define GF_GENERATOR_POLYNOMIAL       0x11D

#define QR_MAX_ALIGNMENT_PATTERN_COUNT  ((COMPUTER_INFO_QR_MAX_VERSION / 7) + 2)

typedef struct {
  UINT8 Bytes[COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH];
  UINTN BitLength;
  UINTN CapacityBytes;
} QR_BIT_BUFFER;

typedef INT8    QR_MODULE_MATRIX[COMPUTER_INFO_QR_MAX_SIZE][COMPUTER_INFO_QR_MAX_SIZE];
typedef BOOLEAN QR_FUNCTION_MATRIX[COMPUTER_INFO_QR_MAX_SIZE][COMPUTER_INFO_QR_MAX_SIZE];

STATIC CONST UINT8 mEccCodewordsPerBlock[COMPUTER_INFO_QR_MAX_VERSION + 1] = {
  0,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30
};

STATIC CONST UINT8 mNumErrorCorrectionBlocks[COMPUTER_INFO_QR_MAX_VERSION + 1] = {
  0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9
};

STATIC UINT8   mGaloisExpTable[GF_SIZE * 2];
STATIC UINT8   mGaloisLogTable[GF_SIZE];
STATIC BOOLEAN mGaloisTablesReady = FALSE;

STATIC
VOID
InitializeGaloisTables(
  VOID
  )
{
  if (mGaloisTablesReady) {
    return;
  }

  UINT16 Value = 1;
  for (UINTN Index = 0; Index < GF_SIZE - 1; Index++) {
    mGaloisExpTable[Index] = (UINT8)Value;
    mGaloisLogTable[Value] = (UINT8)Index;
    Value <<= 1;
    if (Value & GF_SIZE) {
      Value ^= GF_GENERATOR_POLYNOMIAL;
    }
  }

  for (UINTN Index = GF_SIZE - 1; Index < GF_SIZE * 2; Index++) {
    mGaloisExpTable[Index] = mGaloisExpTable[Index - (GF_SIZE - 1)];
  }

  mGaloisTablesReady = TRUE;
}

STATIC
UINT8
GaloisMultiply(
  IN UINT8 A,
  IN UINT8 B
  )
{
  if (A == 0 || B == 0) {
    return 0;
  }

  UINTN LogSum = mGaloisLogTable[A] + mGaloisLogTable[B];
  return mGaloisExpTable[LogSum % (GF_SIZE - 1)];
}

STATIC
UINT8
GaloisPowerOfTwo(
  IN UINTN Exponent
  )
{
  return mGaloisExpTable[Exponent % (GF_SIZE - 1)];
}

STATIC
UINTN
GetNumRawDataModules(
  IN UINTN Version
  )
{
  if ((Version == 0) || (Version > COMPUTER_INFO_QR_MAX_VERSION)) {
    return 0;
  }

  UINTN Result = (16 * Version + 128) * Version + 64;
  if (Version >= 2) {
    UINTN NumAlign = Version / 7 + 2;
    Result -= (25 * NumAlign - 10) * NumAlign - 55;
    if (Version >= 7) {
      Result -= 36;
    }
  }

  return Result;
}

STATIC
UINTN
GetTotalCodewords(
  IN UINTN Version
  )
{
  return GetNumRawDataModules(Version) / 8;
}

STATIC
UINTN
GetRemainderBits(
  IN UINTN Version
  )
{
  return GetNumRawDataModules(Version) % 8;
}

STATIC
UINTN
GetEccCodewordsPerBlock(
  IN UINTN Version
  )
{
  if (Version > COMPUTER_INFO_QR_MAX_VERSION) {
    return 0;
  }
  return mEccCodewordsPerBlock[Version];
}

STATIC
UINTN
GetNumErrorCorrectionBlocks(
  IN UINTN Version
  )
{
  if (Version > COMPUTER_INFO_QR_MAX_VERSION) {
    return 0;
  }
  return mNumErrorCorrectionBlocks[Version];
}

STATIC
UINTN
GetDataCodewordCapacity(
  IN UINTN Version
  )
{
  UINTN Total = GetTotalCodewords(Version);
  UINTN EccPerBlock = GetEccCodewordsPerBlock(Version);
  UINTN NumBlocks = GetNumErrorCorrectionBlocks(Version);
  if ((Total == 0) || (EccPerBlock == 0) || (NumBlocks == 0)) {
    return 0;
  }

  return Total - (EccPerBlock * NumBlocks);
}

STATIC
VOID
GetAlignmentPatternCenters(
  IN  UINTN Version,
  OUT UINT8 *Centers,
  OUT UINTN *Count
  )
{
  if ((Centers == NULL) || (Count == NULL)) {
    return;
  }

  if ((Version == 0) || (Version > COMPUTER_INFO_QR_MAX_VERSION)) {
    *Count = 0;
    return;
  }

  if (Version == 1) {
    *Count = 0;
    return;
  }

  UINTN Size = 4 * Version + 17;
  UINTN NumAlign = Version / 7 + 2;
  UINTN Step = ((Version * 8) + (NumAlign * 3) + 5) / ((NumAlign * 4) - 4);
  Step *= 2;

  UINT8 TempCenters[QR_MAX_ALIGNMENT_PATTERN_COUNT];
  UINTN Index = 0;
  UINTN Position = Size - 7;
  for (UINTN CountIndex = 0; CountIndex < NumAlign - 1; CountIndex++) {
    if (Index < QR_MAX_ALIGNMENT_PATTERN_COUNT) {
      TempCenters[Index] = (UINT8)Position;
    }
    Index++;
    Position -= Step;
  }

  Centers[0] = 6;
  for (UINTN OutputIndex = 0; OutputIndex < Index; OutputIndex++) {
    UINTN SourceIndex = Index - 1 - OutputIndex;
    if ((OutputIndex + 1) < QR_MAX_ALIGNMENT_PATTERN_COUNT) {
      Centers[OutputIndex + 1] = TempCenters[SourceIndex];
    }
  }

  *Count = Index + 1;
}

STATIC
UINT32
ComputeVersionInformation(
  IN UINTN Version
  )
{
  if (Version < 7) {
    return 0;
  }

  UINT32 Remainder = (UINT32)Version;
  for (UINTN Index = 0; Index < 12; Index++) {
    if ((Remainder >> 11) & 0x1) {
      Remainder = (Remainder << 1) ^ 0x1F25;
    } else {
      Remainder <<= 1;
    }
  }

  return ((UINT32)Version << 12) | (Remainder & 0xFFF);
}

STATIC
VOID
BitBufferInit(
  OUT QR_BIT_BUFFER *Buffer,
  IN  UINTN          CapacityBytes
  )
{
  ZeroMem(Buffer->Bytes, sizeof(Buffer->Bytes));
  Buffer->BitLength = 0;
  Buffer->CapacityBytes = CapacityBytes;
}

STATIC
EFI_STATUS
BitBufferAppendBits(
  IN OUT QR_BIT_BUFFER *Buffer,
  IN UINT32             Value,
  IN UINTN              Count
  )
{
  if (Count == 0) {
    return EFI_SUCCESS;
  }

  if (Count > 24) {
    return EFI_INVALID_PARAMETER;
  }

  for (INTN Bit = (INTN)Count - 1; Bit >= 0; Bit--) {
    UINTN ByteIndex = Buffer->BitLength / 8;
    if (ByteIndex >= Buffer->CapacityBytes) {
      return EFI_BUFFER_TOO_SMALL;
    }

    UINTN BitOffset = 7 - (Buffer->BitLength % 8);
    UINT8 Mask = (UINT8)((Value >> Bit) & 0x1);
    Buffer->Bytes[ByteIndex] |= (UINT8)(Mask << BitOffset);
    Buffer->BitLength++;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BuildDataCodewords(
  IN  CONST UINT8 *Payload,
  IN  UINTN        PayloadLength,
  OUT UINT8       *Codewords,
  IN  UINTN        DataCapacity
  )
{
  if ((PayloadLength > DataCapacity) || (DataCapacity == 0) ||
      (DataCapacity > COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  QR_BIT_BUFFER Buffer;
  BitBufferInit(&Buffer, DataCapacity);

  UINTN DataBitCapacity = DataCapacity * 8;

  EFI_STATUS Status;

  Status = BitBufferAppendBits(&Buffer, 0x4, 4);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = BitBufferAppendBits(&Buffer, (UINT32)PayloadLength, 8);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  for (UINTN Index = 0; Index < PayloadLength; Index++) {
    Status = BitBufferAppendBits(&Buffer, Payload[Index], 8);
    if (EFI_ERROR(Status)) {
      return Status;
    }
  }

  if (Buffer.BitLength > DataBitCapacity) {
    return EFI_BAD_BUFFER_SIZE;
  }

  UINTN RemainingBits = DataBitCapacity - Buffer.BitLength;
  UINTN TerminatorBits = (RemainingBits < 4) ? RemainingBits : 4;

  Status = BitBufferAppendBits(&Buffer, 0, TerminatorBits);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if ((Buffer.BitLength % 8) != 0) {
    Status = BitBufferAppendBits(&Buffer, 0, 8 - (Buffer.BitLength % 8));
    if (EFI_ERROR(Status)) {
      return Status;
    }
  }

  BOOLEAN Toggle = TRUE;
  while (Buffer.BitLength < DataBitCapacity) {
    UINT8 Pad = Toggle ? 0xEC : 0x11;
    Status = BitBufferAppendBits(&Buffer, Pad, 8);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    Toggle = !Toggle;
  }

  CopyMem(Codewords, Buffer.Bytes, DataCapacity);
  return EFI_SUCCESS;
}

STATIC
VOID
ComputeGeneratorPolynomial(
  IN  UINTN Degree,
  OUT UINT8 *Result
  )
{
  SetMem(Result, (Degree + 1) * sizeof(UINT8), 0);
  Result[0] = 1;

  for (UINTN D = 0; D < Degree; D++) {
    UINT8 Factor = GaloisPowerOfTwo(D);
    Result[D + 1] = 0;
    for (INTN Index = (INTN)D + 1; Index > 0; Index--) {
      UINT8 Current = Result[Index];
      UINT8 Product = GaloisMultiply(Result[Index - 1], Factor);
      Result[Index] = Current ^ Product;
    }
  }
}

STATIC
VOID
ComputeReedSolomon(
  IN  CONST UINT8 *Data,
  IN  UINTN        DataCount,
  OUT UINT8       *Parity,
  IN  UINTN        ParityCount
  )
{
  SetMem(Parity, ParityCount * sizeof(UINT8), 0);

  UINT8 Generator[COMPUTER_INFO_QR_MAX_ECC_CODEWORDS_PER_BLOCK + 1];
  ComputeGeneratorPolynomial(ParityCount, Generator);

  for (UINTN Index = 0; Index < DataCount; Index++) {
    UINT8 Factor = Data[Index] ^ Parity[0];

    for (UINTN Shift = 0; Shift < ParityCount - 1; Shift++) {
      Parity[Shift] = Parity[Shift + 1];
    }
    Parity[ParityCount - 1] = 0;

    for (UINTN GenIndex = 0; GenIndex < ParityCount; GenIndex++) {
      UINT8 GeneratorCoeff = Generator[GenIndex + 1];
      UINT8 Product = GaloisMultiply(GeneratorCoeff, Factor);
      Parity[GenIndex] ^= Product;
    }
  }
}

STATIC
EFI_STATUS
BuildCodewordSequence(
  IN  CONST UINT8 *DataCodewords,
  IN  UINTN        DataCodewordCount,
  IN  UINTN        TotalCodewords,
  IN  UINTN        NumBlocks,
  IN  UINTN        EccCodewordsPerBlock,
  OUT UINT8       *Codewords
  )
{
  EFI_STATUS Status;
  UINT8 (*Blocks)[COMPUTER_INFO_QR_MAX_TOTAL_CODEWORDS] = NULL;
  UINTN *BlockLengths = NULL;
  UINT8 *Parity = NULL;

  if ((DataCodewords == NULL) || (Codewords == NULL) ||
      (NumBlocks == 0) || (EccCodewordsPerBlock == 0) ||
      (NumBlocks > COMPUTER_INFO_QR_MAX_ERROR_CORRECTION_BLOCKS) ||
      (EccCodewordsPerBlock > COMPUTER_INFO_QR_MAX_ECC_CODEWORDS_PER_BLOCK) ||
      (TotalCodewords > COMPUTER_INFO_QR_MAX_TOTAL_CODEWORDS) ||
      (DataCodewordCount > COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH)) {
    return EFI_INVALID_PARAMETER;
  }

  UINTN RawCodewords = TotalCodewords;
  UINTN NumLongBlocks = RawCodewords % NumBlocks;
  UINTN NumShortBlocks = NumBlocks - NumLongBlocks;
  UINTN ShortBlockTotalLength = RawCodewords / NumBlocks;
  UINTN LongBlockTotalLength = ShortBlockTotalLength + ((NumLongBlocks > 0) ? 1 : 0);

  if (ShortBlockTotalLength < EccCodewordsPerBlock) {
    return EFI_BAD_BUFFER_SIZE;
  }

  UINTN ShortBlockDataLength = ShortBlockTotalLength - EccCodewordsPerBlock;
  UINTN LongBlockDataLength = LongBlockTotalLength - EccCodewordsPerBlock;

  UINTN ExpectedDataCodewords = (ShortBlockDataLength * NumShortBlocks) + (LongBlockDataLength * NumLongBlocks);
  if (ExpectedDataCodewords != DataCodewordCount) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Blocks = AllocateZeroPool(NumBlocks * sizeof(Blocks[0]));
  if (Blocks == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  BlockLengths = AllocateZeroPool(NumBlocks * sizeof(BlockLengths[0]));
  if (BlockLengths == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  Parity = AllocateZeroPool(EccCodewordsPerBlock * sizeof(UINT8));
  if (Parity == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  UINTN Offset = 0;
  for (UINTN BlockIndex = 0; BlockIndex < NumBlocks; BlockIndex++) {
    BOOLEAN IsShortBlock = (BlockIndex < NumShortBlocks);
    UINTN   DataLength   = IsShortBlock ? ShortBlockDataLength : LongBlockDataLength;

    CopyMem(Blocks[BlockIndex], DataCodewords + Offset, DataLength);
    Offset += DataLength;

    ComputeReedSolomon(
      Blocks[BlockIndex],
      DataLength,
      Parity,
      EccCodewordsPerBlock
      );

    UINTN InsertIndex = DataLength;
    if (IsShortBlock) {
      Blocks[BlockIndex][InsertIndex++] = 0;
    }

    CopyMem(&Blocks[BlockIndex][InsertIndex], Parity, EccCodewordsPerBlock);
    BlockLengths[BlockIndex] = InsertIndex + EccCodewordsPerBlock;
  }

  if (Offset != DataCodewordCount) {
    Status = EFI_BAD_BUFFER_SIZE;
    goto Cleanup;
  }

  UINTN BlockLength = BlockLengths[0];
  UINTN CodewordIndex = 0;

  for (UINTN Index = 0; Index < BlockLength; Index++) {
    for (UINTN BlockIndex = 0; BlockIndex < NumBlocks; BlockIndex++) {
      if ((BlockIndex < NumShortBlocks) && (Index == ShortBlockDataLength)) {
        continue;
      }

      if (Index < BlockLengths[BlockIndex]) {
        Codewords[CodewordIndex++] = Blocks[BlockIndex][Index];
      }
    }
  }

  if (CodewordIndex != TotalCodewords) {
    Status = EFI_BAD_BUFFER_SIZE;
    goto Cleanup;
  }

  Status = EFI_SUCCESS;

Cleanup:
  if (Parity != NULL) {
    FreePool(Parity);
  }
  if (BlockLengths != NULL) {
    FreePool(BlockLengths);
  }
  if (Blocks != NULL) {
    FreePool(Blocks);
  }

  return Status;
}

STATIC
VOID
DrawFinderPattern(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     INTN    X,
  IN     INTN    Y,
  IN     UINTN   Size
  )
{
  for (INTN Dy = 0; Dy < 7; Dy++) {
    for (INTN Dx = 0; Dx < 7; Dx++) {
      INTN PosX = X + Dx;
      INTN PosY = Y + Dy;
      if (PosX < 0 || PosY < 0 || PosX >= (INTN)Size || PosY >= (INTN)Size) {
        continue;
      }

      BOOLEAN Outer = (Dx == 0 || Dx == 6 || Dy == 0 || Dy == 6);
      BOOLEAN Inner = (Dx >= 2 && Dx <= 4 && Dy >= 2 && Dy <= 4);
      UINT8 Value = (Outer || Inner) ? 1 : 0;
      Modules[PosY][PosX] = (INT8)Value;
      FunctionModules[PosY][PosX] = TRUE;
    }
  }

  for (INTN Dy = -1; Dy <= 7; Dy++) {
    for (INTN Dx = -1; Dx <= 7; Dx++) {
      INTN PosX = X + Dx;
      INTN PosY = Y + Dy;
      if (PosX < 0 || PosY < 0 || PosX >= (INTN)Size || PosY >= (INTN)Size) {
        continue;
      }

      if (PosX >= X && PosX < X + 7 && PosY >= Y && PosY < Y + 7) {
        continue;
      }

      Modules[PosY][PosX] = 0;
      FunctionModules[PosY][PosX] = TRUE;
    }
  }
}

STATIC
VOID
DrawAlignmentPattern(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     INTN    CenterX,
  IN     INTN    CenterY,
  IN     UINTN   Size
  )
{
  for (INTN Dy = -2; Dy <= 2; Dy++) {
    for (INTN Dx = -2; Dx <= 2; Dx++) {
      INTN PosX = CenterX + Dx;
      INTN PosY = CenterY + Dy;
      if (PosX < 0 || PosY < 0 || PosX >= (INTN)Size || PosY >= (INTN)Size) {
        continue;
      }

      INTN AbsDx = (Dx >= 0) ? Dx : -Dx;
      INTN AbsDy = (Dy >= 0) ? Dy : -Dy;
      INTN Distance = (AbsDx > AbsDy) ? AbsDx : AbsDy;
      UINT8 Value = (UINT8)((Distance != 1) ? 1 : 0);
      Modules[PosY][PosX] = (INT8)Value;
      FunctionModules[PosY][PosX] = TRUE;
    }
  }
}

STATIC
VOID
DrawAlignmentPatterns(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     CONST UINT8          *Centers,
  IN     UINTN                 CenterCount,
  IN     UINTN                 Size
  )
{
  if ((Centers == NULL) || (CenterCount == 0)) {
    return;
  }

  UINT8 LastCenter = Centers[CenterCount - 1];

  for (UINTN YIndex = 0; YIndex < CenterCount; YIndex++) {
    for (UINTN XIndex = 0; XIndex < CenterCount; XIndex++) {
      UINT8 CenterX = Centers[XIndex];
      UINT8 CenterY = Centers[YIndex];

      if (((CenterX == 6) && (CenterY == 6)) ||
          ((CenterX == 6) && (CenterY == LastCenter)) ||
          ((CenterX == LastCenter) && (CenterY == 6))) {
        continue;
      }

      DrawAlignmentPattern(Modules, FunctionModules, CenterX, CenterY, Size);
    }
  }
}

STATIC
VOID
DrawTimingPatterns(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     UINTN                 Size
  )
{
  for (INTN Index = 0; Index < (INTN)Size; Index++) {
    if (!FunctionModules[6][Index]) {
      Modules[6][Index] = (INT8)((Index % 2) == 0);
      FunctionModules[6][Index] = TRUE;
    }
    if (!FunctionModules[Index][6]) {
      Modules[Index][6] = (INT8)((Index % 2) == 0);
      FunctionModules[Index][6] = TRUE;
    }
  }
}

STATIC
VOID
ReserveFormatInfo(
  IN OUT QR_FUNCTION_MATRIX FunctionModules,
  IN     UINTN              Size
  )
{
  for (INTN Index = 0; Index <= 8; Index++) {
    if (Index != 6) {
      FunctionModules[8][Index] = TRUE;
      FunctionModules[Index][8] = TRUE;
    }
  }

  for (INTN Index = 0; Index < 7; Index++) {
    FunctionModules[8][(INTN)Size - 1 - Index] = TRUE;
    FunctionModules[(INTN)Size - 1 - Index][8] = TRUE;
  }

  FunctionModules[8][(INTN)Size - 8] = TRUE;
  FunctionModules[(INTN)Size - 8][8] = TRUE;
}

STATIC
BOOLEAN
IsFunctionModule(
  IN CONST QR_FUNCTION_MATRIX FunctionModules,
  IN INTN                     X,
  IN INTN                     Y,
  IN UINTN                    Size
  )
{
  if (X < 0 || Y < 0 || X >= (INTN)Size || Y >= (INTN)Size) {
    return TRUE;
  }
  return FunctionModules[Y][X];
}

STATIC
VOID
PlaceDataBits(
  IN OUT QR_MODULE_MATRIX            Modules,
  IN     CONST QR_FUNCTION_MATRIX    FunctionModules,
  IN     CONST UINT8                *Bits,
  IN     UINTN                       BitCount,
  IN     UINTN                       Size
  )
{
  UINTN BitIndex = 0;
  BOOLEAN GoingUp = TRUE;

  for (INTN Column = (INTN)Size - 1; Column > 0; Column -= 2) {
    if (Column == 6) {
      Column--;
    }

    for (INTN Offset = 0; Offset < (INTN)Size; Offset++) {
      INTN Row = GoingUp ? ((INTN)Size - 1 - Offset) : Offset;

      for (INTN ColumnOffset = 0; ColumnOffset < 2; ColumnOffset++) {
        INTN CurrentColumn = Column - ColumnOffset;
        if (IsFunctionModule(FunctionModules, CurrentColumn, Row, Size)) {
          continue;
        }

        UINT8 BitValue = 0;
        if (BitIndex < BitCount) {
          BitValue = Bits[BitIndex];
        }
        Modules[Row][CurrentColumn] = (INT8)BitValue;
        BitIndex++;
      }
    }

    GoingUp = !GoingUp;
  }
}

STATIC
UINT8
MaskBit(
  IN UINTN Mask,
  IN INTN  X,
  IN INTN  Y
  )
{
  switch (Mask) {
  case 0:
    return (UINT8)(((X + Y) & 0x1) == 0);
  case 1:
    return (UINT8)((Y & 0x1) == 0);
  case 2:
    return (UINT8)((X % 3) == 0);
  case 3:
    return (UINT8)(((X + Y) % 3) == 0);
  case 4:
    return (UINT8)((((Y / 2) + (X / 3)) & 0x1) == 0);
  case 5:
    return (UINT8)((((X * Y) % 2) + ((X * Y) % 3)) == 0);
  case 6:
    return (UINT8)(((((X * Y) % 2) + ((X * Y) % 3)) & 0x1) == 0);
  case 7:
    return (UINT8)(((((X + Y) % 2) + ((X * Y) % 3)) & 0x1) == 0);
  default:
    return 0;
  }
}

STATIC
VOID
ApplyMask(
  IN OUT QR_MODULE_MATRIX         Modules,
  IN     CONST QR_FUNCTION_MATRIX FunctionModules,
  IN     UINTN                    Mask,
  IN     UINTN                    Size
  )
{
  for (INTN Y = 0; Y < (INTN)Size; Y++) {
    for (INTN X = 0; X < (INTN)Size; X++) {
      if (FunctionModules[Y][X]) {
        continue;
      }
      if (MaskBit(Mask, X, Y)) {
        Modules[Y][X] ^= 1;
      }
    }
  }
}

STATIC
UINT16
CalculateFormatBits(
  IN UINTN Mask
  )
{
  UINT16 Format = 0;
  UINT16 Data = (UINT16)((0x01 << 3) | (Mask & 0x7));
  Format = (UINT16)(Data << 10);

  UINT16 Polynomial = 0x537;
  for (INTN Bit = 14; Bit >= 10; Bit--) {
    if ((Format >> Bit) & 0x1) {
      Format ^= (UINT16)(Polynomial << (Bit - 10));
    }
  }

  Format = (UINT16)((Data << 10) | Format);
  Format ^= 0x5412;
  return Format;
}

STATIC
VOID
DrawFormatBits(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     UINTN                 Mask,
  IN     UINTN                 Size
  )
{
  UINT16 Format = CalculateFormatBits(Mask);

  CONST INTN HorizontalPositions[8] = { 0, 1, 2, 3, 4, 5, 7, 8 };
  CONST INTN VerticalPositions[8]   = { 0, 1, 2, 3, 4, 5, 7, 8 };

  for (INTN Index = 0; Index < 8; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    INTN  Row = VerticalPositions[Index];
    Modules[Row][8] = (INT8)Bit;
    FunctionModules[Row][8] = TRUE;
  }

  for (INTN Index = 0; Index < 8; Index++) {
    UINT8 Bit = (UINT8)((Format >> (14 - Index)) & 0x1);
    INTN  Column = HorizontalPositions[Index];
    Modules[8][Column] = (INT8)Bit;
    FunctionModules[8][Column] = TRUE;
  }

  for (INTN Index = 0; Index < 8; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    INTN  Column = (INTN)Size - 1 - Index;
    Modules[8][Column] = (INT8)Bit;
    FunctionModules[8][Column] = TRUE;
  }

  for (INTN Index = 0; Index < 8; Index++) {
    UINT8 Bit = (UINT8)((Format >> (14 - Index)) & 0x1);
    INTN  Row = (INTN)Size - 1 - Index;
    Modules[Row][8] = (INT8)Bit;
    FunctionModules[Row][8] = TRUE;
  }

  Modules[(INTN)Size - 8][8] = 1;
  FunctionModules[(INTN)Size - 8][8] = TRUE;
}

STATIC
VOID
DrawVersionInformation(
  IN OUT QR_MODULE_MATRIX      Modules,
  IN OUT QR_FUNCTION_MATRIX    FunctionModules,
  IN     UINTN                 Version,
  IN     UINTN                 Size
  )
{
  if (Version < 7) {
    return;
  }

  UINT32 VersionInfo = ComputeVersionInformation(Version);

  for (UINTN Index = 0; Index < 6; Index++) {
    UINT8 Bit0 = (UINT8)((VersionInfo >> (Index * 3)) & 0x1);
    UINT8 Bit1 = (UINT8)((VersionInfo >> ((Index * 3) + 1)) & 0x1);
    UINT8 Bit2 = (UINT8)((VersionInfo >> ((Index * 3) + 2)) & 0x1);

    INTN BottomRow = (INTN)Size - 11;
    Modules[BottomRow][Index] = (INT8)Bit0;
    FunctionModules[BottomRow][Index] = TRUE;
    Modules[BottomRow + 1][Index] = (INT8)Bit1;
    FunctionModules[BottomRow + 1][Index] = TRUE;
    Modules[BottomRow + 2][Index] = (INT8)Bit2;
    FunctionModules[BottomRow + 2][Index] = TRUE;

    INTN RightColumn = (INTN)Size - 11;
    Modules[Index][RightColumn] = (INT8)Bit0;
    FunctionModules[Index][RightColumn] = TRUE;
    Modules[Index][RightColumn + 1] = (INT8)Bit1;
    FunctionModules[Index][RightColumn + 1] = TRUE;
    Modules[Index][RightColumn + 2] = (INT8)Bit2;
    FunctionModules[Index][RightColumn + 2] = TRUE;
  }
}

STATIC
INT32
ScoreRunPenalty(
  IN CONST INT8 *Line,
  IN UINTN       Length
  )
{
  INT32 Penalty = 0;
  INTN RunLength = 1;

  for (INTN Index = 1; Index < (INTN)Length; Index++) {
    if (Line[Index] == Line[Index - 1]) {
      RunLength++;
    } else {
      if (RunLength >= 5) {
        INT32 Excess = (INT32)(RunLength - 5);
        Penalty += 3 + Excess;
      }
      RunLength = 1;
    }
  }

  if (RunLength >= 5) {
    INT32 Excess = (INT32)(RunLength - 5);
    Penalty += 3 + Excess;
  }

  return Penalty;
}

STATIC
INT32
EvaluatePenalty(
  IN CONST QR_MODULE_MATRIX Modules,
  IN UINTN                  Size
  )
{
  INT32 Penalty = 0;

  for (INTN Y = 0; Y < (INTN)Size; Y++) {
    Penalty += ScoreRunPenalty(Modules[Y], Size);
  }

  INT8 Column[COMPUTER_INFO_QR_MAX_SIZE];
  for (INTN X = 0; X < (INTN)Size; X++) {
    for (INTN Y = 0; Y < (INTN)Size; Y++) {
      Column[Y] = Modules[Y][X];
    }
    Penalty += ScoreRunPenalty(Column, Size);
  }

  for (INTN Y = 0; Y < (INTN)Size - 1; Y++) {
    for (INTN X = 0; X < (INTN)Size - 1; X++) {
      INT8 Value = Modules[Y][X];
      if ((Value == Modules[Y][X + 1]) &&
          (Value == Modules[Y + 1][X]) &&
          (Value == Modules[Y + 1][X + 1])) {
        Penalty += 3;
      }
    }
  }

  for (INTN Y = 0; Y < (INTN)Size; Y++) {
    for (INTN X = 0; X <= (INTN)Size - 11; X++) {
      if (Modules[Y][X] && !Modules[Y][X + 1] && Modules[Y][X + 2] && Modules[Y][X + 3] && Modules[Y][X + 4] &&
          !Modules[Y][X + 5] && Modules[Y][X + 6] &&
          !Modules[Y][X + 7] && !Modules[Y][X + 8] && !Modules[Y][X + 9] && !Modules[Y][X + 10]) {
        Penalty += 40;
      }
      if (!Modules[Y][X] && Modules[Y][X + 1] && !Modules[Y][X + 2] && !Modules[Y][X + 3] && !Modules[Y][X + 4] &&
          Modules[Y][X + 5] && !Modules[Y][X + 6] &&
          Modules[Y][X + 7] && Modules[Y][X + 8] && Modules[Y][X + 9] && Modules[Y][X + 10]) {
        Penalty += 40;
      }
    }
  }

  for (INTN X = 0; X < (INTN)Size; X++) {
    for (INTN Y = 0; Y <= (INTN)Size - 11; Y++) {
      if (Modules[Y][X] && !Modules[Y + 1][X] && Modules[Y + 2][X] && Modules[Y + 3][X] && Modules[Y + 4][X] &&
          !Modules[Y + 5][X] && Modules[Y + 6][X] &&
          !Modules[Y + 7][X] && !Modules[Y + 8][X] && !Modules[Y + 9][X] && !Modules[Y + 10][X]) {
        Penalty += 40;
      }
      if (!Modules[Y][X] && Modules[Y + 1][X] && !Modules[Y + 2][X] && !Modules[Y + 3][X] && !Modules[Y + 4][X] &&
          Modules[Y + 5][X] && !Modules[Y + 6][X] &&
          Modules[Y + 7][X] && Modules[Y + 8][X] && Modules[Y + 9][X] && Modules[Y + 10][X]) {
        Penalty += 40;
      }
    }
  }

  UINTN DarkCount = 0;
  for (INTN Y = 0; Y < (INTN)Size; Y++) {
    for (INTN X = 0; X < (INTN)Size; X++) {
      if (Modules[Y][X]) {
        DarkCount++;
      }
    }
  }

  UINTN TotalModules = Size * Size;
  INTN Percent = (INTN)((DarkCount * 100 + TotalModules / 2) / TotalModules);
  INTN FivePercent = ABS(Percent - 50) / 5;
  Penalty += (INT32)FivePercent * 10;

  return Penalty;
}

EFI_STATUS
GenerateComputerInfoQrCode(
  IN  CONST UINT8           *Payload,
  IN  UINTN                 PayloadLength,
  OUT COMPUTER_INFO_QR_CODE *QrCode
  )
{
  EFI_STATUS               Status;
  UINT8                    *DataCodewords        = NULL;
  UINT8                    *Codewords            = NULL;
  UINT8                    *DataBits             = NULL;
  QR_MODULE_MATRIX         *BaseModules          = NULL;
  QR_FUNCTION_MATRIX       *FunctionModules      = NULL;
  QR_MODULE_MATRIX         *BestModules          = NULL;
  QR_MODULE_MATRIX         *MaskedModules        = NULL;
  QR_FUNCTION_MATRIX       *MaskedFunction       = NULL;

  if ((Payload == NULL) || (QrCode == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((PayloadLength == 0) || (PayloadLength > COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  InitializeGaloisTables();

  UINTN SelectedVersion = 0;
  for (UINTN Version = COMPUTER_INFO_QR_MIN_VERSION; Version <= COMPUTER_INFO_QR_MAX_VERSION; Version++) {
    UINTN Capacity = GetDataCodewordCapacity(Version);
    if ((Capacity != 0) && (PayloadLength <= Capacity)) {
      SelectedVersion = Version;
      break;
    }
  }

  if (SelectedVersion == 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  UINTN Size = 4 * SelectedVersion + 17;
  UINTN DataCapacity = GetDataCodewordCapacity(SelectedVersion);
  UINTN TotalCodewords = GetTotalCodewords(SelectedVersion);
  UINTN RemainderBits = GetRemainderBits(SelectedVersion);
  UINTN NumBlocks = GetNumErrorCorrectionBlocks(SelectedVersion);
  UINTN EccCodewordsPerBlock = GetEccCodewordsPerBlock(SelectedVersion);

  UINT8 AlignmentCenters[QR_MAX_ALIGNMENT_PATTERN_COUNT];
  UINTN AlignmentCount;
  GetAlignmentPatternCenters(SelectedVersion, AlignmentCenters, &AlignmentCount);

  UINTN TotalDataBits = TotalCodewords * 8 + RemainderBits;
  DataCodewords = AllocateZeroPool(COMPUTER_INFO_QR_MAX_PAYLOAD_LENGTH);
  if (DataCodewords == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  Status = BuildDataCodewords(Payload, PayloadLength, DataCodewords, DataCapacity);
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }

  Codewords = AllocateZeroPool(COMPUTER_INFO_QR_MAX_TOTAL_CODEWORDS);
  if (Codewords == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  Status = BuildCodewordSequence(
             DataCodewords,
             DataCapacity,
             TotalCodewords,
             NumBlocks,
             EccCodewordsPerBlock,
             Codewords
             );
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }

  DataBits = AllocateZeroPool(COMPUTER_INFO_QR_MAX_TOTAL_CODEWORDS * 8 + 7);
  if (DataBits == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  for (UINTN Bit = 0; Bit < TotalCodewords * 8; Bit++) {
    UINT8 Byte = Codewords[Bit / 8];
    DataBits[Bit] = (UINT8)((Byte >> (7 - (Bit % 8))) & 0x1);
  }
  for (UINTN Bit = TotalCodewords * 8; Bit < TotalDataBits; Bit++) {
    DataBits[Bit] = 0;
  }

  BaseModules = AllocateZeroPool(sizeof(*BaseModules));
  if (BaseModules == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  FunctionModules = AllocateZeroPool(sizeof(*FunctionModules));
  if (FunctionModules == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  DrawFinderPattern(*BaseModules, *FunctionModules, 0, 0, Size);
  DrawFinderPattern(*BaseModules, *FunctionModules, (INTN)Size - 7, 0, Size);
  DrawFinderPattern(*BaseModules, *FunctionModules, 0, (INTN)Size - 7, Size);

  DrawTimingPatterns(*BaseModules, *FunctionModules, Size);

  DrawAlignmentPatterns(*BaseModules, *FunctionModules, AlignmentCenters, AlignmentCount, Size);

  ReserveFormatInfo(*FunctionModules, Size);
  DrawVersionInformation(*BaseModules, *FunctionModules, SelectedVersion, Size);

  (*BaseModules)[(INTN)Size - 8][8] = 1;
  (*FunctionModules)[(INTN)Size - 8][8] = TRUE;

  PlaceDataBits(*BaseModules, *FunctionModules, DataBits, TotalDataBits, Size);

  INT32 BestPenalty = MAX_INT32;

  BestModules = AllocateZeroPool(sizeof(*BestModules));
  if (BestModules == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  MaskedModules = AllocateZeroPool(sizeof(*MaskedModules));
  if (MaskedModules == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  MaskedFunction = AllocateZeroPool(sizeof(*MaskedFunction));
  if (MaskedFunction == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  for (UINTN Mask = 0; Mask < 8; Mask++) {
    CopyMem(*MaskedModules, *BaseModules, sizeof(*BaseModules));
    CopyMem(*MaskedFunction, *FunctionModules, sizeof(*FunctionModules));

    ApplyMask(*MaskedModules, *MaskedFunction, Mask, Size);
    DrawFormatBits(*MaskedModules, *MaskedFunction, Mask, Size);

    INT32 Penalty = EvaluatePenalty(*MaskedModules, Size);
    if (Penalty < BestPenalty) {
      BestPenalty = Penalty;
      CopyMem(*BestModules, *MaskedModules, sizeof(*BestModules));
    }
  }

  for (UINTN Y = 0; Y < Size; Y++) {
    CopyMem(QrCode->Modules[Y], (*BestModules)[Y], Size * sizeof(UINT8));
  }

  QrCode->Size = Size;
  Status = EFI_SUCCESS;

Cleanup:
  if (MaskedFunction != NULL) {
    FreePool(MaskedFunction);
  }
  if (MaskedModules != NULL) {
    FreePool(MaskedModules);
  }
  if (BestModules != NULL) {
    FreePool(BestModules);
  }
  if (FunctionModules != NULL) {
    FreePool(FunctionModules);
  }
  if (BaseModules != NULL) {
    FreePool(BaseModules);
  }
  if (DataBits != NULL) {
    FreePool(DataBits);
  }
  if (Codewords != NULL) {
    FreePool(Codewords);
  }
  if (DataCodewords != NULL) {
    FreePool(DataCodewords);
  }

  return Status;
}
