; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 4
; RUN: llc -mtriple=amdgcn-mesa-mesa3d -mcpu=hawaii < %s | FileCheck -check-prefixes=GFX7 %s

declare float @llvm.experimental.constrained.fpext.f32.f16(half, metadata) #0
declare <2 x float> @llvm.experimental.constrained.fpext.v2f32.v2f16(<2 x half>, metadata) #0

define float @v_constrained_fpext_f16_to_f32(ptr addrspace(1) %ptr) #0 {
; GFX7-LABEL: v_constrained_fpext_f16_to_f32:
; GFX7:       ; %bb.0:
; GFX7-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX7-NEXT:    s_mov_b32 s6, 0
; GFX7-NEXT:    s_mov_b32 s7, 0xf000
; GFX7-NEXT:    s_mov_b32 s4, s6
; GFX7-NEXT:    s_mov_b32 s5, s6
; GFX7-NEXT:    buffer_load_ushort v0, v[0:1], s[4:7], 0 addr64
; GFX7-NEXT:    s_waitcnt vmcnt(0)
; GFX7-NEXT:    v_cvt_f32_f16_e32 v0, v0
; GFX7-NEXT:    s_setpc_b64 s[30:31]
  %val = load half, ptr addrspace(1) %ptr
  %result = call float @llvm.experimental.constrained.fpext.f32.f16(half %val, metadata !"fpexcept.strict")
  ret float %result
}

define <2 x float> @v_constrained_fpext_v2f16_to_v2f32(ptr addrspace(1) %ptr) #0 {
; GFX7-LABEL: v_constrained_fpext_v2f16_to_v2f32:
; GFX7:       ; %bb.0:
; GFX7-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX7-NEXT:    s_mov_b32 s6, 0
; GFX7-NEXT:    s_mov_b32 s7, 0xf000
; GFX7-NEXT:    s_mov_b32 s4, s6
; GFX7-NEXT:    s_mov_b32 s5, s6
; GFX7-NEXT:    buffer_load_dword v1, v[0:1], s[4:7], 0 addr64
; GFX7-NEXT:    s_waitcnt vmcnt(0)
; GFX7-NEXT:    v_cvt_f32_f16_e32 v0, v1
; GFX7-NEXT:    v_lshrrev_b32_e32 v1, 16, v1
; GFX7-NEXT:    v_cvt_f32_f16_e32 v1, v1
; GFX7-NEXT:    s_setpc_b64 s[30:31]
  %val = load <2 x half>, ptr addrspace(1) %ptr
  %result = call <2 x float> @llvm.experimental.constrained.fpext.v2f32.v2f16(<2 x half> %val, metadata !"fpexcept.strict")
  ret <2 x float> %result
}

attributes #0 = { strictfp }