; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=aarch64--linux-gnu -mattr=+sve2p1 < %s | FileCheck %s
; RUN: llc -mtriple=aarch64--linux-gnu -mattr=+sme2p1 < %s | FileCheck %s

;
; ORQV
;

define <16 x i8> @orqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: orqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    orqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.orqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @orqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: orqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    orqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.orqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @orqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: orqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    orqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.orqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @orqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: orqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    orqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.orqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; EORQV
;

define <16 x i8> @eorqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: eorqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    eorqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.eorqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @eorqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: eorqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    eorqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.eorqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @eorqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: eorqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    eorqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.eorqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @eorqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: eorqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    eorqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.eorqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; ANDQV
;

define <16 x i8> @andqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: andqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    andqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.andqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @andqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: andqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    andqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.andqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @andqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: andqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    andqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.andqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @andqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: andqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    andqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.andqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; ADDQV
;

define <16 x i8> @addqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: addqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    addqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.addqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @addqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: addqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    addqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.addqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @addqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: addqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    addqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.addqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @addqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: addqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    addqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.addqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; SMAXQV
;

define <16 x i8> @smaxqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: smaxqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    smaxqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.smaxqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @smaxqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: smaxqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    smaxqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.smaxqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @smaxqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: smaxqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    smaxqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.smaxqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @smaxqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: smaxqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    smaxqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.smaxqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; UMAXQV
;

define <16 x i8> @umaxqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: umaxqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    umaxqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.umaxqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @umaxqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: umaxqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    umaxqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.umaxqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @umaxqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: umaxqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    umaxqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.umaxqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @umaxqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: umaxqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    umaxqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.umaxqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; SMINQV
;

define <16 x i8> @sminqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: sminqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sminqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.sminqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @sminqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: sminqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sminqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.sminqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @sminqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: sminqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sminqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.sminqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @sminqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: sminqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sminqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.sminqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

;
; UMINQV
;

define <16 x i8> @uminqv_i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a) {
; CHECK-LABEL: uminqv_i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    uminqv v0.16b, p0, z0.b
; CHECK-NEXT:    ret
  %res = call <16 x i8> @llvm.aarch64.sve.uminqv.v16i8.nxv16i8(<vscale x 16 x i1> %pg, <vscale x 16 x i8> %a);
  ret <16 x i8> %res
}

define <8 x i16> @uminqv_i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a) {
; CHECK-LABEL: uminqv_i16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    uminqv v0.8h, p0, z0.h
; CHECK-NEXT:    ret
  %res = call <8 x i16> @llvm.aarch64.sve.uminqv.v8i16.nxv8i16(<vscale x 8 x i1> %pg, <vscale x 8 x i16> %a);
  ret <8 x i16> %res
}

define <4 x i32> @uminqv_i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a) {
; CHECK-LABEL: uminqv_i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    uminqv v0.4s, p0, z0.s
; CHECK-NEXT:    ret
  %res = call <4 x i32> @llvm.aarch64.sve.uminqv.v4i32.nxv4i32(<vscale x 4 x i1> %pg, <vscale x 4 x i32> %a);
  ret <4 x i32> %res
}

define <2 x i64> @uminqv_i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a) {
; CHECK-LABEL: uminqv_i64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    uminqv v0.2d, p0, z0.d
; CHECK-NEXT:    ret
  %res = call <2 x i64> @llvm.aarch64.sve.uminqv.v2i64.nxv2i64(<vscale x 2 x i1> %pg, <vscale x 2 x i64> %a);
  ret <2 x i64> %res
}

declare <16 x i8> @llvm.aarch64.sve.orqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.orqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.orqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.orqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.eorqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.eorqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.eorqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.eorqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.andqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.andqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.andqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.andqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.addqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.addqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.addqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.addqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.smaxqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.smaxqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.smaxqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.smaxqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.umaxqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.umaxqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.umaxqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.umaxqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.sminqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.sminqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.sminqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.sminqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)
declare <16 x i8> @llvm.aarch64.sve.uminqv.v16i8.nxv16i8(<vscale x 16 x i1>, <vscale x 16 x i8>)
declare <8 x i16> @llvm.aarch64.sve.uminqv.v8i16.nxv8i16(<vscale x 8 x i1>, <vscale x 8 x i16>)
declare <4 x i32> @llvm.aarch64.sve.uminqv.v4i32.nxv4i32(<vscale x 4 x i1>, <vscale x 4 x i32>)
declare <2 x i64> @llvm.aarch64.sve.uminqv.v2i64.nxv2i64(<vscale x 2 x i1>, <vscale x 2 x i64>)