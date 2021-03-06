/* This file was auto-generated by KreMLin! */
#include "kremlib.h"
#ifndef __Division_H
#define __Division_H


#include "Addition.h"
#include "Comparison.h"
#include "Convert.h"
#include "Shift.h"
#include "testlib.h"

typedef uint64_t *Division_bignum;

extern uint32_t Division_bn_bits2;

void
Division_remainder_loop(
  uint32_t rLen,
  uint32_t modLen,
  uint32_t resLen,
  uint64_t *r_i,
  uint64_t *mod_78,
  uint32_t count1,
  uint64_t *res
);

void
Division_remainder(
  uint32_t aBits,
  uint32_t modBits,
  uint32_t resLen,
  uint64_t *a,
  uint64_t *mod_183,
  uint64_t *res
);
#endif
