#ifndef COMPUTER_INFO_QR_QRCODE_H_
#define COMPUTER_INFO_QR_QRCODE_H_

#include <Uefi.h>

#define COMPUTER_INFO_QR_VERSION             7
#define COMPUTER_INFO_QR_SIZE                (4 * COMPUTER_INFO_QR_VERSION + 17)
#define COMPUTER_INFO_QR_MAX_DATA_LENGTH     156

typedef struct {
  UINTN Size;
  UINT8 Modules[COMPUTER_INFO_QR_SIZE][COMPUTER_INFO_QR_SIZE];
} COMPUTER_INFO_QR_CODE;

EFI_STATUS
GenerateComputerInfoQrCode(
  IN  CONST UINT8              *Payload,
  IN  UINTN                    PayloadLength,
  OUT COMPUTER_INFO_QR_CODE    *QrCode
  );

#endif
