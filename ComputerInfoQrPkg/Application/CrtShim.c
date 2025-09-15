#include <Library/BaseMemoryLib.h>

VOID *
EFIAPI
memset (
  OUT VOID  *Buffer,
  IN  INT32  Value,
  IN  UINTN  Size
  )
{
  SetMem (Buffer, Size, (UINT8)Value);
  return Buffer;
}

VOID *
EFIAPI
memcpy (
  OUT VOID        *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN        Size
  )
{
  return CopyMem (Destination, Source, Size);
}
