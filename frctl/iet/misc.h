#ifndef MISC_H
#define MISC_H

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))
#define hton24(p, v) do { \
        p[0] = (((v) >> 16) & 0xFF); \
        p[1] = (((v) >> 8) & 0xFF); \
        p[2] = ((v) & 0xFF); \
} while (0)

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#define uint64_from_ptr(p) (uint64_t)(uintptr_t)(p)
#define ptr_from_int64(p) (void *)(unsigned long)(p)

static inline int before(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) < 0;
}

#define after(seq2, seq1)       before(seq1, seq2)

static inline int between(u32 seq1, u32 seq2, u32 seq3)
{
        return seq3 - seq2 >= seq1 - seq2;
}

#define MASK_BY_BIT(b)  	((1UL << b) - 1)
#define ALIGN_TO_BIT(x, b)      ((((unsigned long)x) + MASK_BY_BIT(b)) & \
				 ~MASK_BY_BIT(b))
#define ALIGN_TO_32(x)  	ALIGN_TO_BIT(x, 5)

#endif /* MISC_H */
