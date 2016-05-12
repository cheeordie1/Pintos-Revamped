#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define qBits 14
static int32_t f = 1 << qBits;

/* Fixed point number treats first 32 - q bits as integer,
   next q bits as decimal. */
typedef int32_t fp;

/* Convert n to fixed point. */
static inline fp
i_to_fp (int32_t n)
{
  return n * f;
}

/* Convert x to integer (round to zero). */
static inline int32_t
fp_to_iz (fp x)
{
  return x/f;
}

/* Convert x to integer (round nearest). */
static inline int32_t
fp_to_in (fp x)
{
  if (x >= 0)
    return (x + f/2)/f;
  else
    return (x - f/2)/f;
}

/* Add x and y. */
static inline fp
add_fp_fp (fp x, fp y)
{
  return x + y;
}

/* Subtract x and y. */
static inline fp
sub_fp_fp (fp x, fp y)
{
  return x - y;
}

/* Add x and n. */
static inline fp
add_fp_n (fp x, int32_t n)
{
  return x + n * f;
}

/* Subtract n from x. */
static inline fp
sub_fp_n (fp x, int32_t n)
{
  return x - n * f;
}

/* Multiply x by y. */
static inline fp
mult_fp_fp (fp x, fp y)
{
  return ((int64_t) x) * y/f;
}

/* Multiply x by n. */
static inline fp
mult_fp_n (fp x, int32_t n)
{
  return x * n;
}

/* Divide x by y. */
static inline fp
div_fp_fp (fp x, fp y)
{
  return ((int64_t) x) * f/y;
}

/* Divide x by n. */
static inline fp
div_fp_n (fp x, int32_t n)
{
  return x/n;
}

#endif /* threads/fixed-point.h */
