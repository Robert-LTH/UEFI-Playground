#include "QrCode.h"

#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>

#define QR_VERSION                    COMPUTER_INFO_QR_VERSION
#define QR_SIZE_PIXELS                COMPUTER_INFO_QR_SIZE
#define QR_DATA_CODEWORDS             34
#define QR_ECC_CODEWORDS              10
#define QR_TOTAL_CODEWORDS            44
#define QR_REMAINDER_BITS             7
#define QR_DATA_BIT_CAPACITY          (QR_DATA_CODEWORDS * 8)

#define GF_SIZE                       256
#define GF_GENERATOR_POLYNOMIAL       0x11D

typedef struct {
  UINT8 Bytes[QR_DATA_CODEWORDS];
  UINTN BitLength;
} QR_BIT_BUFFER;

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
VOID
BitBufferInit(
  OUT QR_BIT_BUFFER *Buffer
  )
{
  ZeroMem(Buffer->Bytes, sizeof(Buffer->Bytes));
  Buffer->BitLength = 0;
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
    if (ByteIndex >= QR_DATA_CODEWORDS) {
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
  OUT UINT8       *Codewords
  )
{
  if (PayloadLength > COMPUTER_INFO_QR_MAX_DATA_LENGTH) {
    return EFI_BAD_BUFFER_SIZE;
  }

  QR_BIT_BUFFER Buffer;
  BitBufferInit(&Buffer);

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

  if (Buffer.BitLength > QR_DATA_BIT_CAPACITY) {
    return EFI_BAD_BUFFER_SIZE;
  }

  UINTN RemainingBits = QR_DATA_BIT_CAPACITY - Buffer.BitLength;
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
  while (Buffer.BitLength < QR_DATA_BIT_CAPACITY) {
    UINT8 Pad = Toggle ? 0xEC : 0x11;
    Status = BitBufferAppendBits(&Buffer, Pad, 8);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    Toggle = !Toggle;
  }

  CopyMem(Codewords, Buffer.Bytes, QR_DATA_CODEWORDS);
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

  UINT8 Generator[QR_ECC_CODEWORDS + 1];
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
VOID
DrawFinderPattern(
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN OUT BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     INTN    X,
  IN     INTN    Y
  )
{
  for (INTN Dy = 0; Dy < 7; Dy++) {
    for (INTN Dx = 0; Dx < 7; Dx++) {
      INTN PosX = X + Dx;
      INTN PosY = Y + Dy;
      if (PosX < 0 || PosY < 0 || PosX >= QR_SIZE_PIXELS || PosY >= QR_SIZE_PIXELS) {
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
      if (PosX < 0 || PosY < 0 || PosX >= QR_SIZE_PIXELS || PosY >= QR_SIZE_PIXELS) {
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
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN OUT BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     INTN    CenterX,
  IN     INTN    CenterY
  )
{
  for (INTN Dy = -2; Dy <= 2; Dy++) {
    for (INTN Dx = -2; Dx <= 2; Dx++) {
      INTN PosX = CenterX + Dx;
      INTN PosY = CenterY + Dy;
      if (PosX < 0 || PosY < 0 || PosX >= QR_SIZE_PIXELS || PosY >= QR_SIZE_PIXELS) {
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
DrawTimingPatterns(
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN OUT BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS]
  )
{
  for (INTN Index = 0; Index < QR_SIZE_PIXELS; Index++) {
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
  IN OUT BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS]
  )
{
  for (INTN Index = 0; Index <= 8; Index++) {
    if (Index != 6) {
      FunctionModules[8][Index] = TRUE;
      FunctionModules[Index][8] = TRUE;
    }
  }

  for (INTN Index = 0; Index < 7; Index++) {
    FunctionModules[8][QR_SIZE_PIXELS - 1 - Index] = TRUE;
    FunctionModules[QR_SIZE_PIXELS - 1 - Index][8] = TRUE;
  }

  FunctionModules[8][QR_SIZE_PIXELS - 8] = TRUE;
  FunctionModules[QR_SIZE_PIXELS - 8][8] = TRUE;
}

STATIC
BOOLEAN
IsFunctionModule(
  IN BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN INTN    X,
  IN INTN    Y
  )
{
  if (X < 0 || Y < 0 || X >= QR_SIZE_PIXELS || Y >= QR_SIZE_PIXELS) {
    return TRUE;
  }
  return FunctionModules[Y][X];
}

STATIC
VOID
PlaceDataBits(
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     CONST UINT8 *Bits,
  IN     UINTN        BitCount
  )
{
  UINTN BitIndex = 0;
  BOOLEAN GoingUp = TRUE;

  for (INTN Column = QR_SIZE_PIXELS - 1; Column > 0; Column -= 2) {
    if (Column == 6) {
      Column--;
    }

    for (INTN Offset = 0; Offset < QR_SIZE_PIXELS; Offset++) {
      INTN Row = GoingUp ? (QR_SIZE_PIXELS - 1 - Offset) : Offset;

      for (INTN ColumnOffset = 0; ColumnOffset < 2; ColumnOffset++) {
        INTN CurrentColumn = Column - ColumnOffset;
        if (IsFunctionModule(FunctionModules, CurrentColumn, Row)) {
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
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     UINTN   Mask
  )
{
  for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
    for (INTN X = 0; X < QR_SIZE_PIXELS; X++) {
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
  IN OUT INT8    Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN OUT BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS],
  IN     UINTN   Mask
  )
{
  UINT16 Format = CalculateFormatBits(Mask);

  for (INTN Index = 0; Index <= 5; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    Modules[8][Index] = (INT8)Bit;
    FunctionModules[8][Index] = TRUE;
  }

  Modules[8][7] = (INT8)((Format >> 6) & 0x1);
  FunctionModules[8][7] = TRUE;
  Modules[8][8] = (INT8)((Format >> 7) & 0x1);
  FunctionModules[8][8] = TRUE;
  Modules[7][8] = (INT8)((Format >> 8) & 0x1);
  FunctionModules[7][8] = TRUE;

  for (INTN Index = 9; Index < 15; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    Modules[14 - Index][8] = (INT8)Bit;
    FunctionModules[14 - Index][8] = TRUE;
  }

  for (INTN Index = 0; Index < 8; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    Modules[QR_SIZE_PIXELS - 1 - Index][8] = (INT8)Bit;
    FunctionModules[QR_SIZE_PIXELS - 1 - Index][8] = TRUE;
  }

  for (INTN Index = 8; Index < 15; Index++) {
    UINT8 Bit = (UINT8)((Format >> Index) & 0x1);
    Modules[8][QR_SIZE_PIXELS - 15 + Index] = (INT8)Bit;
    FunctionModules[8][QR_SIZE_PIXELS - 15 + Index] = TRUE;
  }

  Modules[8][QR_SIZE_PIXELS - 8] = 1;
  FunctionModules[8][QR_SIZE_PIXELS - 8] = TRUE;
}

STATIC
INT32
ScoreRunPenalty(
  IN INT8 Line[QR_SIZE_PIXELS]
  )
{
  INT32 Penalty = 0;
  INTN RunLength = 1;

  for (INTN Index = 1; Index < QR_SIZE_PIXELS; Index++) {
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
  IN INT8 Modules[QR_SIZE_PIXELS][QR_SIZE_PIXELS]
  )
{
  INT32 Penalty = 0;

  for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
    Penalty += ScoreRunPenalty(Modules[Y]);
  }

  for (INTN X = 0; X < QR_SIZE_PIXELS; X++) {
    INT8 Column[QR_SIZE_PIXELS];
    for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
      Column[Y] = Modules[Y][X];
    }
    Penalty += ScoreRunPenalty(Column);
  }

  for (INTN Y = 0; Y < QR_SIZE_PIXELS - 1; Y++) {
    for (INTN X = 0; X < QR_SIZE_PIXELS - 1; X++) {
      INT8 Value = Modules[Y][X];
      if (Value == Modules[Y][X + 1] &&
          Value == Modules[Y + 1][X] &&
          Value == Modules[Y + 1][X + 1]) {
        Penalty += 3;
      }
    }
  }

  for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
    for (INTN X = 0; X <= QR_SIZE_PIXELS - 11; X++) {
      if (Modules[Y][X] && !Modules[Y][X + 1] && Modules[Y][X + 2] && Modules[Y][X + 3] && Modules[Y][X + 4] && !Modules[Y][X + 5] && Modules[Y][X + 6] &&
          !Modules[Y][X + 7] && !Modules[Y][X + 8] && !Modules[Y][X + 9] && !Modules[Y][X + 10]) {
        Penalty += 40;
      }
      if (!Modules[Y][X] && Modules[Y][X + 1] && !Modules[Y][X + 2] && !Modules[Y][X + 3] && !Modules[Y][X + 4] && Modules[Y][X + 5] && !Modules[Y][X + 6] &&
          Modules[Y][X + 7] && Modules[Y][X + 8] && Modules[Y][X + 9] && Modules[Y][X + 10]) {
        Penalty += 40;
      }
    }
  }

  for (INTN X = 0; X < QR_SIZE_PIXELS; X++) {
    for (INTN Y = 0; Y <= QR_SIZE_PIXELS - 11; Y++) {
      if (Modules[Y][X] && !Modules[Y + 1][X] && Modules[Y + 2][X] && Modules[Y + 3][X] && Modules[Y + 4][X] && !Modules[Y + 5][X] && Modules[Y + 6][X] &&
          !Modules[Y + 7][X] && !Modules[Y + 8][X] && !Modules[Y + 9][X] && !Modules[Y + 10][X]) {
        Penalty += 40;
      }
      if (!Modules[Y][X] && Modules[Y + 1][X] && !Modules[Y + 2][X] && !Modules[Y + 3][X] && !Modules[Y + 4][X] && Modules[Y + 5][X] && !Modules[Y + 6][X] &&
          Modules[Y + 7][X] && Modules[Y + 8][X] && Modules[Y + 9][X] && Modules[Y + 10][X]) {
        Penalty += 40;
      }
    }
  }

  UINTN DarkCount = 0;
  for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
    for (INTN X = 0; X < QR_SIZE_PIXELS; X++) {
      if (Modules[Y][X]) {
        DarkCount++;
      }
    }
  }

  UINTN TotalModules = QR_SIZE_PIXELS * QR_SIZE_PIXELS;
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
  if (Payload == NULL || QrCode == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (PayloadLength == 0 || PayloadLength > COMPUTER_INFO_QR_MAX_DATA_LENGTH) {
    return EFI_BAD_BUFFER_SIZE;
  }

  InitializeGaloisTables();

  UINT8 DataCodewords[QR_DATA_CODEWORDS];
  EFI_STATUS Status = BuildDataCodewords(Payload, PayloadLength, DataCodewords);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  UINT8 EccCodewords[QR_ECC_CODEWORDS];
  ComputeReedSolomon(DataCodewords, QR_DATA_CODEWORDS, EccCodewords, QR_ECC_CODEWORDS);

  UINT8 Codewords[QR_TOTAL_CODEWORDS];
  CopyMem(Codewords, DataCodewords, QR_DATA_CODEWORDS);
  CopyMem(Codewords + QR_DATA_CODEWORDS, EccCodewords, QR_ECC_CODEWORDS);

  UINTN TotalDataBits = QR_TOTAL_CODEWORDS * 8 + QR_REMAINDER_BITS;
  UINT8 DataBits[QR_TOTAL_CODEWORDS * 8 + QR_REMAINDER_BITS];
  for (UINTN Bit = 0; Bit < QR_TOTAL_CODEWORDS * 8; Bit++) {
    UINT8 Byte = Codewords[Bit / 8];
    DataBits[Bit] = (UINT8)((Byte >> (7 - (Bit % 8))) & 0x1);
  }
  for (UINTN Bit = QR_TOTAL_CODEWORDS * 8; Bit < TotalDataBits; Bit++) {
    DataBits[Bit] = 0;
  }

  INT8 BaseModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS];
  BOOLEAN FunctionModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS];
  for (INTN Y = 0; Y < QR_SIZE_PIXELS; Y++) {
    for (INTN X = 0; X < QR_SIZE_PIXELS; X++) {
      BaseModules[Y][X] = 0;
      FunctionModules[Y][X] = FALSE;
    }
  }

  DrawFinderPattern(BaseModules, FunctionModules, 0, 0);
  DrawFinderPattern(BaseModules, FunctionModules, QR_SIZE_PIXELS - 7, 0);
  DrawFinderPattern(BaseModules, FunctionModules, 0, QR_SIZE_PIXELS - 7);

  DrawTimingPatterns(BaseModules, FunctionModules);

  DrawAlignmentPattern(BaseModules, FunctionModules, QR_SIZE_PIXELS - 7, QR_SIZE_PIXELS - 7);

  ReserveFormatInfo(FunctionModules);

  BaseModules[QR_SIZE_PIXELS - 8][8] = 1;
  FunctionModules[QR_SIZE_PIXELS - 8][8] = TRUE;

  PlaceDataBits(BaseModules, FunctionModules, DataBits, TotalDataBits);

  INT32 BestPenalty = MAX_INT32;
  INT8 BestModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS];

  for (UINTN Mask = 0; Mask < 8; Mask++) {
    INT8 MaskedModules[QR_SIZE_PIXELS][QR_SIZE_PIXELS];
    BOOLEAN MaskedFunction[QR_SIZE_PIXELS][QR_SIZE_PIXELS];
    CopyMem(MaskedModules, BaseModules, sizeof(BaseModules));
    CopyMem(MaskedFunction, FunctionModules, sizeof(FunctionModules));

    ApplyMask(MaskedModules, MaskedFunction, Mask);
    DrawFormatBits(MaskedModules, MaskedFunction, Mask);

    INT32 Penalty = EvaluatePenalty(MaskedModules);
    if (Penalty < BestPenalty) {
      BestPenalty = Penalty;
      CopyMem(BestModules, MaskedModules, sizeof(BestModules));
    }
  }

  CopyMem(QrCode->Modules, BestModules, sizeof(BestModules));
  QrCode->Size = QR_SIZE_PIXELS;
  return EFI_SUCCESS;
}
