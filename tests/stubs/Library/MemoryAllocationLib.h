#ifndef TESTS_STUBS_LIBRARY_MEMORYALLOCATIONLIB_H_
#define TESTS_STUBS_LIBRARY_MEMORYALLOCATIONLIB_H_

#include "../Uefi.h"
#include <stdlib.h>

STATIC inline VOID *
AllocateZeroPool(
  IN UINTN AllocationSize
  )
{
  return (AllocationSize == 0) ? NULL : calloc(1, AllocationSize);
}

STATIC inline VOID
FreePool(
  IN VOID *Buffer
  )
{
  free(Buffer);
}

#endif  // TESTS_STUBS_LIBRARY_MEMORYALLOCATIONLIB_H_
