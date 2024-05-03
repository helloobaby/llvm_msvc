//===-- Single-precision erf(x) function ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/math/erff.h"
#include "src/__support/FPUtil/FPBits.h"
#include "src/__support/FPUtil/PolyEval.h"
#include "src/__support/FPUtil/except_value_utils.h"
#include "src/__support/FPUtil/multiply_add.h"
#include "src/__support/common.h"
#include "src/__support/macros/optimization.h" // LIBC_UNLIKELY

namespace LIBC_NAMESPACE {

// Polynomials approximating erf(x)/x on ( k/8, (k + 1)/8 ) generated by Sollya
// with:
// > P = fpminimax(erf(x)/x, [|0, 2, 4, 6, 8, 10, 12, 14|], [|D...|],
//                 [k/8, (k + 1)/8]);
// for k = 0..31.
constexpr double COEFFS[32][8] = {
    {0x1.20dd750429b6dp0, -0x1.812746b037753p-2, 0x1.ce2f219e8596ap-4,
     -0x1.b82cdacb78fdap-6, 0x1.56479297dfda5p-8, -0x1.8b3ac5455ef02p-11,
     -0x1.126fcac367e3bp-8, 0x1.2d0bdb3ba4984p-4},
    {0x1.20dd750429b6dp0, -0x1.812746b0379a8p-2, 0x1.ce2f21a03cf2ap-4,
     -0x1.b82ce30de083ep-6, 0x1.565bcad3eb60fp-8, -0x1.c02c66f659256p-11,
     0x1.f92f673385229p-14, -0x1.def402648ae9p-17},
    {0x1.20dd750429b34p0, -0x1.812746b032dcep-2, 0x1.ce2f219d84aaep-4,
     -0x1.b82ce22dcf139p-6, 0x1.565b9efcd4af1p-8, -0x1.c021f1af414bcp-11,
     0x1.f7c6d177eff82p-14, -0x1.c9e4410dcf865p-17},
    {0x1.20dd750426eabp0, -0x1.812746ae592c7p-2, 0x1.ce2f211525f14p-4,
     -0x1.b82ccc125e63fp-6, 0x1.56596f261cfd3p-8, -0x1.bfde1ff8eeecfp-11,
     0x1.f31a9d15dc5d8p-14, -0x1.a5a4362844b3cp-17},
    {0x1.20dd75039c705p0, -0x1.812746777e74dp-2, 0x1.ce2f17af98a1bp-4,
     -0x1.b82be4b817cbep-6, 0x1.564bec2e2962ep-8, -0x1.bee86f9da3558p-11,
     0x1.e9443689dc0ccp-14, -0x1.79c0f230805d8p-17},
    {0x1.20dd74f811211p0, -0x1.81274371a3e8fp-2, 0x1.ce2ec038262e5p-4,
     -0x1.b8265b82c5e1fp-6, 0x1.5615a2e239267p-8, -0x1.bc63ae023dcebp-11,
     0x1.d87c2102f7e06p-14, -0x1.49584bea41d62p-17},
    {0x1.20dd746d063e3p0, -0x1.812729a8a950fp-2, 0x1.ce2cb0a2df232p-4,
     -0x1.b80eca1f51278p-6, 0x1.5572e26c46815p-8, -0x1.b715e5638b65ep-11,
     0x1.bfbb195484968p-14, -0x1.177a565c15c52p-17},
    {0x1.20dd701b44486p0, -0x1.812691145f237p-2, 0x1.ce23a06b8cfd9p-4,
     -0x1.b7c1dc7245288p-6, 0x1.53e92f7f397ddp-8, -0x1.ad97cc4acf0b2p-11,
     0x1.9f028b2b09b71p-14, -0x1.cdc4da08da8c1p-18},
    {0x1.20dd5715ac332p0, -0x1.8123e680bd0ebp-2, 0x1.ce0457aded691p-4,
     -0x1.b6f52d52bed4p-6, 0x1.50c291b84414cp-8, -0x1.9ea246b1ad4a9p-11,
     0x1.77654674e0cap-14, -0x1.737c11a1bcebbp-18},
    {0x1.20dce6593e114p0, -0x1.811a59c02eadcp-2, 0x1.cdab53c7cd7d5p-4,
     -0x1.b526d2e321eedp-6, 0x1.4b1d32cd8b994p-8, -0x1.8963143ec0a1ep-11,
     0x1.4ad5700e4db91p-14, -0x1.231e100e43ef2p-18},
    {0x1.20db48bfd5a62p0, -0x1.80fdd84f9e308p-2, 0x1.ccd340d462983p-4,
     -0x1.b196a2928768p-6, 0x1.4210c2c13a0f7p-8, -0x1.6dbdfb4ff71aep-11,
     0x1.1bca2d17fbd71p-14, -0x1.bca36f90c7cf5p-19},
    {0x1.20d64b2f8f508p0, -0x1.80b4d4f19fa8bp-2, 0x1.cb088197262e3p-4,
     -0x1.ab51fd02e5b99p-6, 0x1.34e1e5e81a632p-8, -0x1.4c66377b502cep-11,
     0x1.d9ad25066213cp-15, -0x1.4b0df7dd0cfa1p-19},
    {0x1.20c8fc1243576p0, -0x1.8010cb2009e27p-2, 0x1.c7a47e9299315p-4,
     -0x1.a155be5683654p-6, 0x1.233502694997bp-8, -0x1.26c94b7d813p-11,
     0x1.8094f1de25fb9p-15, -0x1.e0e3d776c6eefp-20},
    {0x1.20a9bd1611bc1p0, -0x1.7ec7fbce83f9p-2, 0x1.c1d757d7317b7p-4,
     -0x1.92c160cd589fp-6, 0x1.0d307269cc5c2p-8, -0x1.fda5b0d2d1879p-12,
     0x1.2fdd7b3b14a7fp-15, -0x1.54eed4a26af5ap-20},
    {0x1.20682834f943dp0, -0x1.7c73f747bf5a9p-2, 0x1.b8c2db4a9ffd1p-4,
     -0x1.7f0e4ffe989ecp-6, 0x1.e7061eae4166ep-9, -0x1.ad36e873fff2dp-12,
     0x1.d39222396128ep-16, -0x1.d83dacec5ea6bp-21},
    {0x1.1feb8d12676d7p0, -0x1.7898347284afep-2, 0x1.aba3466b34451p-4,
     -0x1.663adc573e2f9p-6, 0x1.ae99fb17c3e08p-9, -0x1.602f950ad5535p-12,
     0x1.5e9717490609dp-16, -0x1.3fca107bbc8d5p-21},
    {0x1.1f12fe3c536fap0, -0x1.72b1d1f22e6d3p-2, 0x1.99fc0eed4a896p-4,
     -0x1.48db0a87bd8c6p-6, 0x1.73e368895aa61p-9, -0x1.19b35d5301fc8p-12,
     0x1.007987e4bb033p-16, -0x1.a7edcd4c2dc7p-22},
    {0x1.1db7b0df84d5dp0, -0x1.6a4e4a41cde02p-2, 0x1.83bbded16455dp-4,
     -0x1.2809b3b36977ep-6, 0x1.39c08bab44679p-9, -0x1.b7b45a70ed119p-13,
     0x1.6e99b36410e7bp-17, -0x1.13619bb7ebc0cp-22},
    {0x1.1bb1c85c4a527p0, -0x1.5f23b99a249a3p-2, 0x1.694c91fa0d12cp-4,
     -0x1.053e1ce11c72dp-6, 0x1.02bf72c50ea78p-9, -0x1.4f478fb56cb02p-13,
     0x1.005f80ecbe213p-17, -0x1.5f2446bde7f5bp-23},
    {0x1.18dec3bd51f9dp0, -0x1.5123f58346186p-2, 0x1.4b8a1ca536ab4p-4,
     -0x1.c4243015cc723p-7, 0x1.a1a8a01d351efp-10, -0x1.f466b34f1d86bp-14,
     0x1.5f835eea0bf6ap-18, -0x1.b83165b939234p-24},
    {0x1.152804c3369f4p0, -0x1.4084cd4afd4bcp-2, 0x1.2ba2e836e47aap-4,
     -0x1.800f2dfc6904bp-7, 0x1.4a6daf0669c59p-10, -0x1.6e326ab872317p-14,
     0x1.d9761a6a755a5p-19, -0x1.0fca33f9dd4b5p-24},
    {0x1.1087ad68356aap0, -0x1.2dbb044707459p-2, 0x1.0aea8ceaa0384p-4,
     -0x1.40b516d52b3d2p-7, 0x1.00c9e05f01d22p-10, -0x1.076afb0dc0ff7p-14,
     0x1.39fadec400657p-19, -0x1.4b5761352e7e3p-25},
    {0x1.0b0a7a8ba4a22p0, -0x1.196990d22d4a1p-2, 0x1.d5551e6ac0c4dp-5,
     -0x1.07cce1770bd1ap-7, 0x1.890347b8848bfp-11, -0x1.757ec96750b6ap-15,
     0x1.9b258a1e06bcep-20, -0x1.8fc6d22da7572p-26},
    {0x1.04ce2be70fb47p0, -0x1.0449e4b0b9cacp-2, 0x1.97f7424f4b0e7p-5,
     -0x1.ac825439c42f4p-8, 0x1.28f5f65426dfbp-11, -0x1.05b699a90f90fp-15,
     0x1.0a888eecf4593p-20, -0x1.deace2b32bb31p-27},
    {0x1.fbf9fb0e11cc8p-1, -0x1.de2640856545ap-3, 0x1.5f5b1f47f851p-5,
     -0x1.588bc71eb41b9p-8, 0x1.bc6a0a772f56dp-12, -0x1.6b9fad1f1657ap-16,
     0x1.573204ba66504p-21, -0x1.1d38065c94e44p-27},
    {0x1.ed8f18c99e031p-1, -0x1.b4cb6acd903b4p-3, 0x1.2c7f3dddd6fc1p-5,
     -0x1.13052067df4ep-8, 0x1.4a5027444082fp-12, -0x1.f672bab0e2554p-17,
     0x1.b83c756348cc9p-22, -0x1.534f1a1079499p-28},
    {0x1.debd33044166dp-1, -0x1.8d7cd9053f7d8p-3, 0x1.ff9957fb3d6e7p-6,
     -0x1.b50be55de0f36p-9, 0x1.e92c8ec53a628p-13, -0x1.5a4b88d508007p-17,
     0x1.1a27737559e26p-22, -0x1.942ae62cb2c14p-29},
    {0x1.cfdbf0386f3bdp-1, -0x1.68e33d93b0dc4p-3, 0x1.b2683d58f53dep-6,
     -0x1.5a9174e70d26fp-9, 0x1.69ddd326d49cdp-13, -0x1.dd8f397a8219cp-18,
     0x1.6a755016ad4ddp-23, -0x1.e366e0139187dp-30},
    {0x1.c132adb8d7464p-1, -0x1.475a899f61b46p-3, 0x1.70a431397a77cp-6,
     -0x1.12e3d35beeee2p-9, 0x1.0c16b05738333p-13, -0x1.4a47f873e144ep-18,
     0x1.d3d494c698c02p-24, -0x1.2302c59547fe5p-30},
    {0x1.b2f5fd05555e7p-1, -0x1.28feefbe03ec7p-3, 0x1.3923acbb3a676p-6,
     -0x1.b4ff793cd6358p-10, 0x1.8ea0eb8c913bcp-14, -0x1.cb31ec2baceb1p-19,
     0x1.30011e7e80c04p-24, -0x1.617710635cb1dp-31},
    {0x1.a54853cd9593ep-1, -0x1.0dbdbaea4dc8ep-3, 0x1.0a93e2c20a0fdp-6,
     -0x1.5c969ff401ea8p-10, 0x1.29e0cc64fe627p-14, -0x1.4160d8e9d3c2ap-19,
     0x1.8e7b67594624ap-25, -0x1.b1cf2c975b09bp-32},
    {0x1.983ceece09ff8p-1, -0x1.eacc78f7a2dp-4, 0x1.c74418410655fp-7,
     -0x1.1756a050e441ep-10, 0x1.bff3650f7f548p-15, -0x1.c56c0217d3adap-20,
     0x1.07b4918d0b489p-25, -0x1.0d4be8c1c50f8p-32},
};

LLVM_LIBC_FUNCTION(float, erff, (float x)) {
  using FPBits = typename fputil::FPBits<float>;
  FPBits xbits(x);

  uint32_t x_u = xbits.uintval();
  uint32_t x_abs = x_u & 0x7fff'ffffU;

  // Exceptional values
  if (LIBC_UNLIKELY(x_abs == 0x3f65'9229U)) // |x| = 0x1.cb2452p-1f
    return x < 0.0f ? fputil::round_result_slightly_down(-0x1.972ea8p-1f)
                    : fputil::round_result_slightly_up(0x1.972ea8p-1f);
  if (LIBC_UNLIKELY(x_abs == 0x4004'1e6aU)) // |x| = 0x1.083cd4p+1f
    return x < 0.0f ? fputil::round_result_slightly_down(-0x1.fe3462p-1f)
                    : fputil::round_result_slightly_up(0x1.fe3462p-1f);

  // if (LIBC_UNLIKELY(x_abs > 0x407a'd444U)) {
  if (LIBC_UNLIKELY(x_abs >= 0x4080'0000U)) {
    const float ONE[2] = {1.0f, -1.0f};
    const float SMALL[2] = {-0x1.0p-25f, 0x1.0p-25f};

    int sign = static_cast<int>(xbits.get_sign());

    if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
      return (x_abs > 0x7f80'0000) ? x : ONE[sign];
    }

    return ONE[sign] + SMALL[sign];
  }

  // Polynomial approximation:
  //   erf(x) ~ x * (c0 + c1 * x^2 + c2 * x^4 + ... + c7 * x^14)
  double xd = static_cast<double>(x);
  double xsq = xd * xd;

  const uint32_t EIGHT = 3 << FPBits::FRACTION_LEN;
  int idx = static_cast<int>(FPBits(x_abs + EIGHT).get_val());

  double x4 = xsq * xsq;
  double c0 = fputil::multiply_add(xsq, COEFFS[idx][1], COEFFS[idx][0]);
  double c1 = fputil::multiply_add(xsq, COEFFS[idx][3], COEFFS[idx][2]);
  double c2 = fputil::multiply_add(xsq, COEFFS[idx][5], COEFFS[idx][4]);
  double c3 = fputil::multiply_add(xsq, COEFFS[idx][7], COEFFS[idx][6]);

  double x8 = x4 * x4;
  double p0 = fputil::multiply_add(x4, c1, c0);
  double p1 = fputil::multiply_add(x4, c3, c2);

  return static_cast<float>(xd * fputil::multiply_add(x8, p1, p0));
}

} // namespace LIBC_NAMESPACE
