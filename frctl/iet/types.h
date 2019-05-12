#ifndef _TYPES_H
#define _TYPES_H

#include <sys/types.h>
#include <byteswap.h>
#include <endian.h>
#include <stdint.h>
#include <inttypes.h>

#if __BYTE_ORDER == __BIG_ENDIAN
# define cpu_to_le16(x)         bswap_16(x)
# define le16_to_cpu(x)         bswap_16(x)
# define cpu_to_le32(x)         bswap_32(x)
# define le32_to_cpu(x)         bswap_32(x)
# define cpu_to_be16(x)         (x)
# define be16_to_cpu(x)         (x)
# define cpu_to_be32(x)         (x)
# define be32_to_cpu(x)         (x)
# define cpu_to_be64(x)         (x)
# define be64_to_cpu(x)         (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
# define cpu_to_le16(x)         (x)
# define le16_to_cpu(x)         (x)
# define cpu_to_le32(x)         (x)
# define le32_to_cpu(x)         (x)
# define cpu_to_be16(x)         bswap_16(x)
# define be16_to_cpu(x)         bswap_16(x)
# define cpu_to_be32(x)         bswap_32(x)
# define be32_to_cpu(x)         bswap_32(x)
# define cpu_to_be64(x)         bswap_64(x)
# define be64_to_cpu(x)         bswap_64(x)
#else
#error "unknown endianess!"
#endif

/* min()/max() that do strict type-checking. Lifted from the kernel. */
#define min(x, y) ({                            \
        typeof(x) _min1 = (x);                  \
        typeof(y) _min2 = (y);                  \
        (void) (&_min1 == &_min2);              \
        _min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({                            \
        typeof(x) _max1 = (x);                  \
        typeof(y) _max2 = (y);                  \
        (void) (&_max1 == &_max2);              \
        _max1 > _max2 ? _max1 : _max2; })

/* ... and their non-checking counterparts. */
#define min_t(type, x, y) ({                    \
        type _min1 = (x);                       \
        type _min2 = (y);                       \
        _min1 < _min2 ? _min1 : _min2; })

#define max_t(type, x, y) ({                    \
        type _max1 = (x);                       \
        type _max2 = (y);                       \
        _max1 > _max2 ? _max1 : _max2; })

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#endif /* _TYPES_H */
