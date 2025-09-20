#ifndef TESTS_STUBS_UEFI_H_
#define TESTS_STUBS_UEFI_H_

#include <stddef.h>
#include <stdint.h>

#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define STATIC static

typedef void     VOID;
typedef uint8_t  BOOLEAN;
typedef int8_t   INT8;
typedef uint8_t  UINT8;
typedef int16_t  INT16;
typedef uint16_t UINT16;
typedef int32_t  INT32;
typedef uint32_t UINT32;
typedef int64_t  INT64;
typedef uint64_t UINT64;
typedef size_t   UINTN;
typedef long     INTN;

typedef UINT64 EFI_STATUS;

#define TRUE  ((BOOLEAN)1)
#define FALSE ((BOOLEAN)0)

#define EFI_SUCCESS           0ULL
#define EFI_INVALID_PARAMETER 2ULL
#define EFI_BAD_BUFFER_SIZE   3ULL
#define EFI_BUFFER_TOO_SMALL  4ULL
#define EFI_OUT_OF_RESOURCES  5ULL

#define EFI_ERROR(Status) ((Status) != EFI_SUCCESS)

#define MAX_INT32  0x7FFFFFFF
#define ABS(Value) (((Value) < 0) ? -(Value) : (Value))

#endif  // TESTS_STUBS_UEFI_H_
