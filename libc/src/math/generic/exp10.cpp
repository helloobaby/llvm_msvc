//===-- Double-precision 10^x function ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/math/exp10.h"
#include "common_constants.h" // Lookup tables EXP2_MID1 and EXP_M2.
#include "explogxf.h"         // ziv_test_denorm.
#include "src/__support/CPP/bit.h"
#include "src/__support/CPP/optional.h"
#include "src/__support/FPUtil/FEnvImpl.h"
#include "src/__support/FPUtil/FPBits.h"
#include "src/__support/FPUtil/PolyEval.h"
#include "src/__support/FPUtil/double_double.h"
#include "src/__support/FPUtil/dyadic_float.h"
#include "src/__support/FPUtil/multiply_add.h"
#include "src/__support/FPUtil/nearest_integer.h"
#include "src/__support/FPUtil/rounding_mode.h"
#include "src/__support/FPUtil/triple_double.h"
#include "src/__support/common.h"
#include "src/__support/macros/optimization.h" // LIBC_UNLIKELY

#include <errno.h>

namespace LIBC_NAMESPACE {

using fputil::DoubleDouble;
using fputil::TripleDouble;
using Float128 = typename fputil::DyadicFloat<128>;

// log2(10)
constexpr double LOG2_10 = 0x1.a934f0979a371p+1;

// -2^-12 * log10(2)
// > a = -2^-12 * log10(2);
// > b = round(a, 32, RN);
// > c = round(a - b, 32, RN);
// > d = round(a - b - c, D, RN);
// Errors < 1.5 * 2^-144
constexpr double MLOG10_2_EXP2_M12_HI = -0x1.3441350ap-14;
constexpr double MLOG10_2_EXP2_M12_MID = 0x1.0c0219dc1da99p-51;
constexpr double MLOG10_2_EXP2_M12_MID_32 = 0x1.0c0219dcp-51;
constexpr double MLOG10_2_EXP2_M12_LO = 0x1.da994fd20dba2p-87;

// Error bounds:
// Errors when using double precision.
constexpr double ERR_D = 0x1.8p-63;

// Errors when using double-double precision.
constexpr double ERR_DD = 0x1.8p-99;

// Polynomial approximations with double precision.  Generated by Sollya with:
// > P = fpminimax((10^x - 1)/x, 3, [|D...|], [-2^-14, 2^-14]);
// > P;
// Error bounds:
//   | output - (10^dx - 1) / dx | < 2^-52.
LIBC_INLINE double poly_approx_d(double dx) {
  // dx^2
  double dx2 = dx * dx;
  double c0 =
      fputil::multiply_add(dx, 0x1.53524c73cea6ap+1, 0x1.26bb1bbb55516p+1);
  double c1 =
      fputil::multiply_add(dx, 0x1.2bd75cc6afc65p+0, 0x1.0470587aa264cp+1);
  double p = fputil::multiply_add(dx2, c1, c0);
  return p;
}

// Polynomial approximation with double-double precision.  Generated by Solya
// with:
// > P = fpminimax((10^x - 1)/x, 5, [|DD...|], [-2^-14, 2^-14]);
// Error bounds:
//   | output - 10^(dx) | < 2^-101
DoubleDouble poly_approx_dd(const DoubleDouble &dx) {
  // Taylor polynomial.
  constexpr DoubleDouble COEFFS[] = {
      {0, 0x1p0},
      {-0x1.f48ad494e927bp-53, 0x1.26bb1bbb55516p1},
      {-0x1.e2bfab3191cd2p-53, 0x1.53524c73cea69p1},
      {0x1.80fb65ec3b503p-53, 0x1.0470591de2ca4p1},
      {0x1.338fc05e21e55p-54, 0x1.2bd7609fd98c4p0},
      {0x1.d4ea116818fbp-56, 0x1.1429ffd519865p-1},
      {-0x1.872a8ff352077p-57, 0x1.a7ed70847c8b3p-3},

  };

  DoubleDouble p = fputil::polyeval(dx, COEFFS[0], COEFFS[1], COEFFS[2],
                                    COEFFS[3], COEFFS[4], COEFFS[5], COEFFS[6]);
  return p;
}

// Polynomial approximation with 128-bit precision:
// Return exp(dx) ~ 1 + a0 * dx + a1 * dx^2 + ... + a6 * dx^7
// For |dx| < 2^-14:
//   | output - 10^dx | < 1.5 * 2^-124.
Float128 poly_approx_f128(const Float128 &dx) {
  using MType = typename Float128::MantissaType;

  constexpr Float128 COEFFS_128[]{
      {false, -127, MType({0, 0x8000000000000000})}, // 1.0
      {false, -126, MType({0xea56d62b82d30a2d, 0x935d8dddaaa8ac16})},
      {false, -126, MType({0x80a99ce75f4d5bdb, 0xa9a92639e753443a})},
      {false, -126, MType({0x6a4f9d7dbf6c9635, 0x82382c8ef1652304})},
      {false, -124, MType({0x345787019216c7af, 0x12bd7609fd98c44c})},
      {false, -127, MType({0xcc41ed7e0d27aee5, 0x450a7ff47535d889})},
      {false, -130, MType({0x8326bb91a6e7601d, 0xd3f6b844702d636b})},
      {false, -130, MType({0xfa7b46df314112a9, 0x45b937f0d05bb1cd})},
  };

  Float128 p = fputil::polyeval(dx, COEFFS_128[0], COEFFS_128[1], COEFFS_128[2],
                                COEFFS_128[3], COEFFS_128[4], COEFFS_128[5],
                                COEFFS_128[6], COEFFS_128[7]);
  return p;
}

// Compute 10^(x) using 128-bit precision.
// TODO(lntue): investigate triple-double precision implementation for this
// step.
Float128 exp10_f128(double x, double kd, int idx1, int idx2) {
  double t1 = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_HI, x); // exact
  double t2 = kd * MLOG10_2_EXP2_M12_MID_32;                     // exact
  double t3 = kd * MLOG10_2_EXP2_M12_LO; // Error < 2^-144

  Float128 dx = fputil::quick_add(
      Float128(t1), fputil::quick_add(Float128(t2), Float128(t3)));

  // TODO: Skip recalculating exp_mid1 and exp_mid2.
  Float128 exp_mid1 =
      fputil::quick_add(Float128(EXP2_MID1[idx1].hi),
                        fputil::quick_add(Float128(EXP2_MID1[idx1].mid),
                                          Float128(EXP2_MID1[idx1].lo)));

  Float128 exp_mid2 =
      fputil::quick_add(Float128(EXP2_MID2[idx2].hi),
                        fputil::quick_add(Float128(EXP2_MID2[idx2].mid),
                                          Float128(EXP2_MID2[idx2].lo)));

  Float128 exp_mid = fputil::quick_mul(exp_mid1, exp_mid2);

  Float128 p = poly_approx_f128(dx);

  Float128 r = fputil::quick_mul(exp_mid, p);

  r.exponent += static_cast<int>(kd) >> 12;

  return r;
}

// Compute 10^x with double-double precision.
DoubleDouble exp10_double_double(double x, double kd,
                                 const DoubleDouble &exp_mid) {
  // Recalculate dx:
  //   dx = x - k * 2^-12 * log10(2)
  double t1 = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_HI, x); // exact
  double t2 = kd * MLOG10_2_EXP2_M12_MID_32;                     // exact
  double t3 = kd * MLOG10_2_EXP2_M12_LO; // Error < 2^-140

  DoubleDouble dx = fputil::exact_add(t1, t2);
  dx.lo += t3;

  // Degree-6 polynomial approximation in double-double precision.
  // | p - 10^x | < 2^-103.
  DoubleDouble p = poly_approx_dd(dx);

  // Error bounds: 2^-102.
  DoubleDouble r = fputil::quick_mult(exp_mid, p);

  return r;
}

// When output is denormal.
double exp10_denorm(double x) {
  // Range reduction.
  double tmp = fputil::multiply_add(x, LOG2_10, 0x1.8000'0000'4p21);
  int k = static_cast<int>(cpp::bit_cast<uint64_t>(tmp) >> 19);
  double kd = static_cast<double>(k);

  uint32_t idx1 = (k >> 6) & 0x3f;
  uint32_t idx2 = k & 0x3f;

  int hi = k >> 12;

  DoubleDouble exp_mid1{EXP2_MID1[idx1].mid, EXP2_MID1[idx1].hi};
  DoubleDouble exp_mid2{EXP2_MID2[idx2].mid, EXP2_MID2[idx2].hi};
  DoubleDouble exp_mid = fputil::quick_mult(exp_mid1, exp_mid2);

  // |dx| < 1.5 * 2^-15 + 2^-31 < 2^-14
  double lo_h = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_HI, x); // exact
  double dx = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_MID, lo_h);

  double mid_lo = dx * exp_mid.hi;

  // Approximate (10^dx - 1)/dx ~ 1 + a0*dx + a1*dx^2 + a2*dx^3 + a3*dx^4.
  double p = poly_approx_d(dx);

  double lo = fputil::multiply_add(p, mid_lo, exp_mid.lo);

  if (auto r = ziv_test_denorm(hi, exp_mid.hi, lo, ERR_D);
      LIBC_LIKELY(r.has_value()))
    return r.value();

  // Use double-double
  DoubleDouble r_dd = exp10_double_double(x, kd, exp_mid);

  if (auto r = ziv_test_denorm(hi, r_dd.hi, r_dd.lo, ERR_DD);
      LIBC_LIKELY(r.has_value()))
    return r.value();

  // Use 128-bit precision
  Float128 r_f128 = exp10_f128(x, kd, idx1, idx2);

  return static_cast<double>(r_f128);
}

// Check for exceptional cases when:
//  * log10(1 - 2^-54) < x < log10(1 + 2^-53)
//  * x >= log10(2^1024)
//  * x <= log10(2^-1022)
//  * x is inf or nan
double set_exceptional(double x) {
  using FPBits = typename fputil::FPBits<double>;
  FPBits xbits(x);

  uint64_t x_u = xbits.uintval();
  uint64_t x_abs = xbits.abs().uintval();

  // |x| < log10(1 + 2^-53)
  if (x_abs <= 0x3c8bcb7b1526e50e) {
    // 10^(x) ~ 1 + x/2
    return fputil::multiply_add(x, 0.5, 1.0);
  }

  // x <= log10(2^-1022) || x >= log10(2^1024) or inf/nan.
  if (x_u >= 0xc0733a7146f72a42) {
    // x <= log10(2^-1075) or -inf/nan
    if (x_u > 0xc07439b746e36b52) {
      // exp(-Inf) = 0
      if (xbits.is_inf())
        return 0.0;

      // exp(nan) = nan
      if (xbits.is_nan())
        return x;

      if (fputil::quick_get_round() == FE_UPWARD)
        return FPBits::min_denormal();
      fputil::set_errno_if_required(ERANGE);
      fputil::raise_except_if_required(FE_UNDERFLOW);
      return 0.0;
    }

    return exp10_denorm(x);
  }

  // x >= log10(2^1024) or +inf/nan
  // x is finite
  if (x_u < 0x7ff0'0000'0000'0000ULL) {
    int rounding = fputil::quick_get_round();
    if (rounding == FE_DOWNWARD || rounding == FE_TOWARDZERO)
      return FPBits::max_normal();

    fputil::set_errno_if_required(ERANGE);
    fputil::raise_except_if_required(FE_OVERFLOW);
  }
  // x is +inf or nan
  return x + static_cast<double>(FPBits::inf());
}

LLVM_LIBC_FUNCTION(double, exp10, (double x)) {
  using FPBits = typename fputil::FPBits<double>;
  using FloatProp = typename fputil::FloatProperties<double>;
  FPBits xbits(x);

  uint64_t x_u = xbits.uintval();

  // x <= log10(2^-1022) or x >= log10(2^1024) or
  // log10(1 - 2^-54) < x < log10(1 + 2^-53).
  if (LIBC_UNLIKELY(x_u >= 0xc0733a7146f72a42 ||
                    (x_u <= 0xbc7bcb7b1526e50e && x_u >= 0x40734413509f79ff) ||
                    x_u < 0x3c8bcb7b1526e50e)) {
    return set_exceptional(x);
  }

  // Now log10(2^-1075) < x <= log10(1 - 2^-54) or
  //     log10(1 + 2^-53) < x < log10(2^1024)

  // Range reduction:
  // Let x = log10(2) * (hi + mid1 + mid2) + lo
  // in which:
  //   hi is an integer
  //   mid1 * 2^6 is an integer
  //   mid2 * 2^12 is an integer
  // then:
  //   10^(x) = 2^hi * 2^(mid1) * 2^(mid2) * 10^(lo).
  // With this formula:
  //   - multiplying by 2^hi is exact and cheap, simply by adding the exponent
  //     field.
  //   - 2^(mid1) and 2^(mid2) are stored in 2 x 64-element tables.
  //   - 10^(lo) ~ 1 + a0*lo + a1 * lo^2 + ...
  //
  // We compute (hi + mid1 + mid2) together by perform the rounding on
  //   x * log2(10) * 2^12.
  // Since |x| < |log10(2^-1075)| < 2^9,
  //   |x * 2^12| < 2^9 * 2^12 < 2^21,
  // So we can fit the rounded result round(x * 2^12) in int32_t.
  // Thus, the goal is to be able to use an additional addition and fixed width
  // shift to get an int32_t representing round(x * 2^12).
  //
  // Assuming int32_t using 2-complement representation, since the mantissa part
  // of a double precision is unsigned with the leading bit hidden, if we add an
  // extra constant C = 2^e1 + 2^e2 with e1 > e2 >= 2^23 to the product, the
  // part that are < 2^e2 in resulted mantissa of (x*2^12*L2E + C) can be
  // considered as a proper 2-complement representations of x*2^12.
  //
  // One small problem with this approach is that the sum (x*2^12 + C) in
  // double precision is rounded to the least significant bit of the dorminant
  // factor C.  In order to minimize the rounding errors from this addition, we
  // want to minimize e1.  Another constraint that we want is that after
  // shifting the mantissa so that the least significant bit of int32_t
  // corresponds to the unit bit of (x*2^12*L2E), the sign is correct without
  // any adjustment.  So combining these 2 requirements, we can choose
  //   C = 2^33 + 2^32, so that the sign bit corresponds to 2^31 bit, and hence
  // after right shifting the mantissa, the resulting int32_t has correct sign.
  // With this choice of C, the number of mantissa bits we need to shift to the
  // right is: 52 - 33 = 19.
  //
  // Moreover, since the integer right shifts are equivalent to rounding down,
  // we can add an extra 0.5 so that it will become round-to-nearest, tie-to-
  // +infinity.  So in particular, we can compute:
  //   hmm = x * 2^12 + C,
  // where C = 2^33 + 2^32 + 2^-1, then if
  //   k = int32_t(lower 51 bits of double(x * 2^12 + C) >> 19),
  // the reduced argument:
  //   lo = x - log10(2) * 2^-12 * k is bounded by:
  //   |lo|  = |x - log10(2) * 2^-12 * k|
  //         = log10(2) * 2^-12 * | x * log2(10) * 2^12 - k |
  //        <= log10(2) * 2^-12 * (2^-1 + 2^-19)
  //         < 1.5 * 2^-2 * (2^-13 + 2^-31)
  //         = 1.5 * (2^-15 * 2^-31)
  //
  // Finally, notice that k only uses the mantissa of x * 2^12, so the
  // exponent 2^12 is not needed.  So we can simply define
  //   C = 2^(33 - 12) + 2^(32 - 12) + 2^(-13 - 12), and
  //   k = int32_t(lower 51 bits of double(x + C) >> 19).

  // Rounding errors <= 2^-31.
  double tmp = fputil::multiply_add(x, LOG2_10, 0x1.8000'0000'4p21);
  int k = static_cast<int>(cpp::bit_cast<uint64_t>(tmp) >> 19);
  double kd = static_cast<double>(k);

  uint32_t idx1 = (k >> 6) & 0x3f;
  uint32_t idx2 = k & 0x3f;

  int hi = k >> 12;

  DoubleDouble exp_mid1{EXP2_MID1[idx1].mid, EXP2_MID1[idx1].hi};
  DoubleDouble exp_mid2{EXP2_MID2[idx2].mid, EXP2_MID2[idx2].hi};
  DoubleDouble exp_mid = fputil::quick_mult(exp_mid1, exp_mid2);

  // |dx| < 1.5 * 2^-15 + 2^-31 < 2^-14
  double lo_h = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_HI, x); // exact
  double dx = fputil::multiply_add(kd, MLOG10_2_EXP2_M12_MID, lo_h);

  // We use the degree-4 polynomial to approximate 10^(lo):
  //   10^(lo) ~ 1 + a0 * lo + a1 * lo^2 + a2 * lo^3 + a3 * lo^4
  //           = 1 + lo * P(lo)
  // So that the errors are bounded by:
  //   |P(lo) - (10^lo - 1)/lo| < |lo|^4 / 64 < 2^(-13 * 4) / 64 = 2^-58
  // Let P_ be an evaluation of P where all intermediate computations are in
  // double precision.  Using either Horner's or Estrin's schemes, the evaluated
  // errors can be bounded by:
  //      |P_(lo) - P(lo)| < 2^-51
  //   => |lo * P_(lo) - (2^lo - 1) | < 2^-65
  //   => 2^(mid1 + mid2) * |lo * P_(lo) - expm1(lo)| < 2^-64.
  // Since we approximate
  //   2^(mid1 + mid2) ~ exp_mid.hi + exp_mid.lo,
  // We use the expression:
  //    (exp_mid.hi + exp_mid.lo) * (1 + dx * P_(dx)) ~
  //  ~ exp_mid.hi + (exp_mid.hi * dx * P_(dx) + exp_mid.lo)
  // with errors bounded by 2^-64.

  double mid_lo = dx * exp_mid.hi;

  // Approximate (10^dx - 1)/dx ~ 1 + a0*dx + a1*dx^2 + a2*dx^3 + a3*dx^4.
  double p = poly_approx_d(dx);

  double lo = fputil::multiply_add(p, mid_lo, exp_mid.lo);

  double upper = exp_mid.hi + (lo + ERR_D);
  double lower = exp_mid.hi + (lo - ERR_D);

  if (LIBC_LIKELY(upper == lower)) {
    // To multiply by 2^hi, a fast way is to simply add hi to the exponent
    // field.
    int64_t exp_hi = static_cast<int64_t>(hi) << FloatProp::FRACTION_LEN;
    double r = cpp::bit_cast<double>(exp_hi + cpp::bit_cast<int64_t>(upper));
    return r;
  }

  // Exact outputs when x = 1, 2, ..., 22 + hard to round with x = 23.
  // Quick check mask: 0x800f'ffffU = ~(bits of 1.0 | ... | bits of 23.0)
  if (LIBC_UNLIKELY((x_u & 0x8000'ffff'ffff'ffffULL) == 0ULL)) {
    switch (x_u) {
    case 0x3ff0000000000000: // x = 1.0
      return 10.0;
    case 0x4000000000000000: // x = 2.0
      return 100.0;
    case 0x4008000000000000: // x = 3.0
      return 1'000.0;
    case 0x4010000000000000: // x = 4.0
      return 10'000.0;
    case 0x4014000000000000: // x = 5.0
      return 100'000.0;
    case 0x4018000000000000: // x = 6.0
      return 1'000'000.0;
    case 0x401c000000000000: // x = 7.0
      return 10'000'000.0;
    case 0x4020000000000000: // x = 8.0
      return 100'000'000.0;
    case 0x4022000000000000: // x = 9.0
      return 1'000'000'000.0;
    case 0x4024000000000000: // x = 10.0
      return 10'000'000'000.0;
    case 0x4026000000000000: // x = 11.0
      return 100'000'000'000.0;
    case 0x4028000000000000: // x = 12.0
      return 1'000'000'000'000.0;
    case 0x402a000000000000: // x = 13.0
      return 10'000'000'000'000.0;
    case 0x402c000000000000: // x = 14.0
      return 100'000'000'000'000.0;
    case 0x402e000000000000: // x = 15.0
      return 1'000'000'000'000'000.0;
    case 0x4030000000000000: // x = 16.0
      return 10'000'000'000'000'000.0;
    case 0x4031000000000000: // x = 17.0
      return 100'000'000'000'000'000.0;
    case 0x4032000000000000: // x = 18.0
      return 1'000'000'000'000'000'000.0;
    case 0x4033000000000000: // x = 19.0
      return 10'000'000'000'000'000'000.0;
    case 0x4034000000000000: // x = 20.0
      return 100'000'000'000'000'000'000.0;
    case 0x4035000000000000: // x = 21.0
      return 1'000'000'000'000'000'000'000.0;
    case 0x4036000000000000: // x = 22.0
      return 10'000'000'000'000'000'000'000.0;
    case 0x4037000000000000: // x = 23.0
      return 0x1.52d02c7e14af6p76 + x;
    }
  }

  // Use double-double
  DoubleDouble r_dd = exp10_double_double(x, kd, exp_mid);

  double upper_dd = r_dd.hi + (r_dd.lo + ERR_DD);
  double lower_dd = r_dd.hi + (r_dd.lo - ERR_DD);

  if (LIBC_LIKELY(upper_dd == lower_dd)) {
    // To multiply by 2^hi, a fast way is to simply add hi to the exponent
    // field.
    int64_t exp_hi = static_cast<int64_t>(hi) << FloatProp::FRACTION_LEN;
    double r = cpp::bit_cast<double>(exp_hi + cpp::bit_cast<int64_t>(upper_dd));
    return r;
  }

  // Use 128-bit precision
  Float128 r_f128 = exp10_f128(x, kd, idx1, idx2);

  return static_cast<double>(r_f128);
}

} // namespace LIBC_NAMESPACE
