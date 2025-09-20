#ifndef TESTS_STUBS_LIBRARY_BASEMEMORYLIB_H_
#define TESTS_STUBS_LIBRARY_BASEMEMORYLIB_H_

#include "../Uefi.h"
#include <string.h>

STATIC inline VOID *
CopyMem(
  OUT VOID       *Destination,
  IN  CONST VOID *Source,
  IN  UINTN       Length
  )
{
  return memcpy(Destination, Source, Length);
}

STATIC inline VOID *
SetMem(
  OUT VOID *Buffer,
  IN  UINTN Length,
  IN  UINT8 Value
  )
{
  return memset(Buffer, Value, Length);
}

STATIC inline VOID *
ZeroMem(
  OUT VOID *Buffer,
  IN  UINTN Length
  )
{
  return memset(Buffer, 0, Length);
}

#endif  // TESTS_STUBS_LIBRARY_BASEMEMORYLIB_H_
