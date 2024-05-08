; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -march=amdgcn -mcpu=gfx1200 -verify-machineinstrs < %s | FileCheck -enable-var-scope -check-prefixes=GCN,GFX12-SDAG %s
; RUN: llc -global-isel -march=amdgcn -mcpu=gfx1200 -verify-machineinstrs < %s | FileCheck -enable-var-scope -check-prefixes=GCN,GFX12-GISEL %s

define amdgpu_ps float @test_fminimum_f32_vv(float %a, float %b) {
; GCN-LABEL: test_fminimum_f32_vv:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v1
; GCN-NEXT:    ; return to shader part epilog
  %val = call float @llvm.minimum.f32(float %a, float %b)
  ret float %val
}

define amdgpu_ps float @test_fminimum_f32_ss(float inreg %a, float inreg %b) {
; GCN-LABEL: test_fminimum_f32_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_minimum_f32 s0, s0, s1
; GCN-NEXT:    s_delay_alu instid0(SALU_CYCLE_3)
; GCN-NEXT:    v_mov_b32_e32 v0, s0
; GCN-NEXT:    ; return to shader part epilog
  %val = call float @llvm.minimum.f32(float %a, float %b)
  ret float %val
}

define amdgpu_ps float @test_fminimum_f32_vs(float %a, float inreg %b) {
; GCN-LABEL: test_fminimum_f32_vs:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, s0
; GCN-NEXT:    ; return to shader part epilog
  %val = call float @llvm.minimum.f32(float %a, float %b)
  ret float %val
}

define amdgpu_ps float @test_fminimum_nnan_f32(float %a, float %b) {
; GCN-LABEL: test_fminimum_nnan_f32:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v1
; GCN-NEXT:    ; return to shader part epilog
  %val = call nnan float @llvm.minimum.f32(float %a, float %b)
  ret float %val
}

define amdgpu_ps <2 x float> @test_fminimum_v2f32(<2 x float> %a, <2 x float> %b) {
; GCN-LABEL: test_fminimum_v2f32:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v2
; GCN-NEXT:    v_minimum_f32 v1, v1, v3
; GCN-NEXT:    ; return to shader part epilog
  %val = call <2 x float> @llvm.minimum.v2f32(<2 x float> %a, <2 x float> %b)
  ret <2 x float> %val
}

define amdgpu_ps <2 x float> @test_fminimum_v2f32_ss(<2 x float> inreg %a, <2 x float> inreg %b) {
; GCN-LABEL: test_fminimum_v2f32_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_minimum_f32 s0, s0, s2
; GCN-NEXT:    s_minimum_f32 s1, s1, s3
; GCN-NEXT:    s_delay_alu instid0(SALU_CYCLE_3)
; GCN-NEXT:    v_dual_mov_b32 v0, s0 :: v_dual_mov_b32 v1, s1
; GCN-NEXT:    ; return to shader part epilog
  %val = call <2 x float> @llvm.minimum.v2f32(<2 x float> %a, <2 x float> %b)
  ret <2 x float> %val
}

define amdgpu_ps <3 x float> @test_fminimum_v3f32(<3 x float> %a, <3 x float> %b) {
; GCN-LABEL: test_fminimum_v3f32:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v3
; GCN-NEXT:    v_minimum_f32 v1, v1, v4
; GCN-NEXT:    v_minimum_f32 v2, v2, v5
; GCN-NEXT:    ; return to shader part epilog
  %val = call <3 x float> @llvm.minimum.v3f32(<3 x float> %a, <3 x float> %b)
  ret <3 x float> %val
}

define amdgpu_ps <4 x float> @test_fminimum_v4f32(<4 x float> %a, <4 x float> %b) {
; GCN-LABEL: test_fminimum_v4f32:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v4
; GCN-NEXT:    v_minimum_f32 v1, v1, v5
; GCN-NEXT:    v_minimum_f32 v2, v2, v6
; GCN-NEXT:    v_minimum_f32 v3, v3, v7
; GCN-NEXT:    ; return to shader part epilog
  %val = call <4 x float> @llvm.minimum.v4f32(<4 x float> %a, <4 x float> %b)
  ret <4 x float> %val
}

define amdgpu_ps <16 x float> @test_fminimum_v16f32(<16 x float> %a, <16 x float> %b) {
; GCN-LABEL: test_fminimum_v16f32:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f32 v0, v0, v16
; GCN-NEXT:    v_minimum_f32 v1, v1, v17
; GCN-NEXT:    v_minimum_f32 v2, v2, v18
; GCN-NEXT:    v_minimum_f32 v3, v3, v19
; GCN-NEXT:    v_minimum_f32 v4, v4, v20
; GCN-NEXT:    v_minimum_f32 v5, v5, v21
; GCN-NEXT:    v_minimum_f32 v6, v6, v22
; GCN-NEXT:    v_minimum_f32 v7, v7, v23
; GCN-NEXT:    v_minimum_f32 v8, v8, v24
; GCN-NEXT:    v_minimum_f32 v9, v9, v25
; GCN-NEXT:    v_minimum_f32 v10, v10, v26
; GCN-NEXT:    v_minimum_f32 v11, v11, v27
; GCN-NEXT:    v_minimum_f32 v12, v12, v28
; GCN-NEXT:    v_minimum_f32 v13, v13, v29
; GCN-NEXT:    v_minimum_f32 v14, v14, v30
; GCN-NEXT:    v_minimum_f32 v15, v15, v31
; GCN-NEXT:    ; return to shader part epilog
  %val = call <16 x float> @llvm.minimum.v16f32(<16 x float> %a, <16 x float> %b)
  ret <16 x float> %val
}

define amdgpu_ps half @test_fminimum_f16_vv(half %a, half %b) {
; GCN-LABEL: test_fminimum_f16_vv:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f16 v0, v0, v1
; GCN-NEXT:    ; return to shader part epilog
  %val = call half @llvm.minimum.f16(half %a, half %b)
  ret half %val
}

define amdgpu_ps half @test_fminimum_f16_ss(half inreg %a, half inreg %b) {
; GCN-LABEL: test_fminimum_f16_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_minimum_f16 s0, s0, s1
; GCN-NEXT:    s_delay_alu instid0(SALU_CYCLE_3)
; GCN-NEXT:    v_mov_b32_e32 v0, s0
; GCN-NEXT:    ; return to shader part epilog
  %val = call half @llvm.minimum.f16(half %a, half %b)
  ret half %val
}

define amdgpu_ps <2 x half> @test_fminimum_v2f16_vv(<2 x half> %a, <2 x half> %b) {
; GCN-LABEL: test_fminimum_v2f16_vv:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, v0, v1
; GCN-NEXT:    ; return to shader part epilog
  %val = call <2 x half> @llvm.minimum.v2f16(<2 x half> %a, <2 x half> %b)
  ret <2 x half> %val
}

define amdgpu_ps <2 x half> @test_fminimum_v2f16_ss(<2 x half> inreg %a, <2 x half> inreg %b) {
; GCN-LABEL: test_fminimum_v2f16_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, s0, s1
; GCN-NEXT:    ; return to shader part epilog
  %val = call <2 x half> @llvm.minimum.v2f16(<2 x half> %a, <2 x half> %b)
  ret <2 x half> %val
}

define amdgpu_ps <3 x half> @test_fminimum_v3f16_vv(<3 x half> %a, <3 x half> %b) {
; GCN-LABEL: test_fminimum_v3f16_vv:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, v0, v2
; GCN-NEXT:    v_minimum_f16 v1, v1, v3
; GCN-NEXT:    ; return to shader part epilog
  %val = call <3 x half> @llvm.minimum.v3f16(<3 x half> %a, <3 x half> %b)
  ret <3 x half> %val
}

define amdgpu_ps <3 x half> @test_fminimum_v3f16_ss(<3 x half> inreg %a, <3 x half> inreg %b) {
; GCN-LABEL: test_fminimum_v3f16_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, s0, s2
; GCN-NEXT:    s_minimum_f16 s0, s1, s3
; GCN-NEXT:    s_delay_alu instid0(SALU_CYCLE_3)
; GCN-NEXT:    v_mov_b32_e32 v1, s0
; GCN-NEXT:    ; return to shader part epilog
  %val = call <3 x half> @llvm.minimum.v3f16(<3 x half> %a, <3 x half> %b)
  ret <3 x half> %val
}

define amdgpu_ps <4 x half> @test_fminimum_v4f16(<4 x half> %a, <4 x half> %b) {
; GCN-LABEL: test_fminimum_v4f16:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, v0, v2
; GCN-NEXT:    v_pk_minimum_f16 v1, v1, v3
; GCN-NEXT:    ; return to shader part epilog
  %val = call <4 x half> @llvm.minimum.v4f16(<4 x half> %a, <4 x half> %b)
  ret <4 x half> %val
}

define amdgpu_ps <4 x half> @test_fminimum_v4f16_ss(<4 x half> inreg %a, <4 x half> inreg %b) {
; GCN-LABEL: test_fminimum_v4f16_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_pk_minimum_f16 v0, s0, s2
; GCN-NEXT:    v_pk_minimum_f16 v1, s1, s3
; GCN-NEXT:    ; return to shader part epilog
  %val = call <4 x half> @llvm.minimum.v4f16(<4 x half> %a, <4 x half> %b)
  ret <4 x half> %val
}

define amdgpu_ps <2 x float> @test_fminimum_f64_vv(double %a, double %b) {
; GCN-LABEL: test_fminimum_f64_vv:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f64 v[0:1], v[0:1], v[2:3]
; GCN-NEXT:    ; return to shader part epilog
  %val = call double @llvm.minimum.f64(double %a, double %b)
  %ret = bitcast double %val to <2 x float>
  ret <2 x float> %ret
}

define amdgpu_ps <2 x float> @test_fminimum_f64_ss(double inreg %a, double inreg %b) {
; GCN-LABEL: test_fminimum_f64_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f64 v[0:1], s[0:1], s[2:3]
; GCN-NEXT:    ; return to shader part epilog
  %val = call double @llvm.minimum.f64(double %a, double %b)
  %ret = bitcast double %val to <2 x float>
  ret <2 x float> %ret
}

define amdgpu_ps <4 x float> @test_fminimum_v2f64_ss(<2 x double> inreg %a, <2 x double> inreg %b) {
; GCN-LABEL: test_fminimum_v2f64_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f64 v[0:1], s[0:1], s[4:5]
; GCN-NEXT:    v_minimum_f64 v[2:3], s[2:3], s[6:7]
; GCN-NEXT:    ; return to shader part epilog
  %val = call <2 x double> @llvm.minimum.v2f64(<2 x double> %a, <2 x double> %b)
  %ret = bitcast <2 x double> %val to <4 x float>
  ret <4 x float> %ret
}

define amdgpu_ps <8 x float> @test_fminimum_v4f64(<4 x double> %a, <4 x double> %b) {
; GCN-LABEL: test_fminimum_v4f64:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f64 v[0:1], v[0:1], v[8:9]
; GCN-NEXT:    v_minimum_f64 v[2:3], v[2:3], v[10:11]
; GCN-NEXT:    v_minimum_f64 v[4:5], v[4:5], v[12:13]
; GCN-NEXT:    v_minimum_f64 v[6:7], v[6:7], v[14:15]
; GCN-NEXT:    ; return to shader part epilog
  %val = call <4 x double> @llvm.minimum.v4f64(<4 x double> %a, <4 x double> %b)
  %ret = bitcast <4 x double> %val to <8 x float>
  ret <8 x float> %ret
}

define amdgpu_ps <8 x float> @test_fminimum_v4f64_ss(<4 x double> inreg %a, <4 x double> inreg %b) {
; GCN-LABEL: test_fminimum_v4f64_ss:
; GCN:       ; %bb.0:
; GCN-NEXT:    v_minimum_f64 v[0:1], s[0:1], s[8:9]
; GCN-NEXT:    v_minimum_f64 v[2:3], s[2:3], s[10:11]
; GCN-NEXT:    v_minimum_f64 v[4:5], s[4:5], s[12:13]
; GCN-NEXT:    v_minimum_f64 v[6:7], s[6:7], s[14:15]
; GCN-NEXT:    ; return to shader part epilog
  %val = call <4 x double> @llvm.minimum.v4f64(<4 x double> %a, <4 x double> %b)
  %ret = bitcast <4 x double> %val to <8 x float>
  ret <8 x float> %ret
}

define amdgpu_kernel void @fminimumi_f32_move_to_valu(ptr addrspace(1) %out, ptr addrspace(1) %aptr, ptr addrspace(1) %bptr) {
; GCN-LABEL: fminimumi_f32_move_to_valu:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_clause 0x1
; GCN-NEXT:    s_load_b128 s[4:7], s[0:1], 0x24
; GCN-NEXT:    s_load_b64 s[0:1], s[0:1], 0x34
; GCN-NEXT:    v_mov_b32_e32 v0, 0
; GCN-NEXT:    s_waitcnt lgkmcnt(0)
; GCN-NEXT:    global_load_b32 v1, v0, s[6:7] th:TH_LOAD_RT_NT
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:    global_load_b32 v2, v0, s[0:1] th:TH_LOAD_RT_NT
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:    v_minimum_f32 v1, v1, v2
; GCN-NEXT:    global_store_b32 v0, v1, s[4:5]
; GCN-NEXT:    s_nop 0
; GCN-NEXT:    s_sendmsg sendmsg(MSG_DEALLOC_VGPRS)
; GCN-NEXT:    s_endpgm
  %a = load volatile float, ptr addrspace(1) %aptr, align 4
  %b = load volatile float, ptr addrspace(1) %bptr, align 4
  %v = call float @llvm.minimum.f32(float %a, float %b)
  store float %v, ptr addrspace(1) %out, align 4
  ret void
}

define amdgpu_kernel void @fminimum_f16_move_to_valu(ptr addrspace(1) %out, ptr addrspace(1) %aptr, ptr addrspace(1) %bptr) {
; GCN-LABEL: fminimum_f16_move_to_valu:
; GCN:       ; %bb.0:
; GCN-NEXT:    s_clause 0x1
; GCN-NEXT:    s_load_b128 s[4:7], s[0:1], 0x24
; GCN-NEXT:    s_load_b64 s[0:1], s[0:1], 0x34
; GCN-NEXT:    v_mov_b32_e32 v0, 0
; GCN-NEXT:    s_waitcnt lgkmcnt(0)
; GCN-NEXT:    global_load_u16 v1, v0, s[6:7] th:TH_LOAD_RT_NT
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:    global_load_u16 v2, v0, s[0:1] th:TH_LOAD_RT_NT
; GCN-NEXT:    s_waitcnt vmcnt(0)
; GCN-NEXT:    v_minimum_f16 v1, v1, v2
; GCN-NEXT:    global_store_b16 v0, v1, s[4:5]
; GCN-NEXT:    s_nop 0
; GCN-NEXT:    s_sendmsg sendmsg(MSG_DEALLOC_VGPRS)
; GCN-NEXT:    s_endpgm
  %a = load volatile half, ptr addrspace(1) %aptr, align 4
  %b = load volatile half, ptr addrspace(1) %bptr, align 4
  %v = call half @llvm.minimum.f16(half %a, half %b)
  store half %v, ptr addrspace(1) %out, align 4
  ret void
}

declare float @llvm.minimum.f32(float, float)
declare <2 x float> @llvm.minimum.v2f32(<2 x float>, <2 x float>)
declare <3 x float> @llvm.minimum.v3f32(<3 x float>, <3 x float>)
declare <4 x float> @llvm.minimum.v4f32(<4 x float>, <4 x float>)
declare <16 x float> @llvm.minimum.v16f32(<16 x float>, <16 x float>)
declare half @llvm.minimum.f16(half, half)
declare <2 x half> @llvm.minimum.v2f16(<2 x half>, <2 x half>)
declare <3 x half> @llvm.minimum.v3f16(<3 x half>, <3 x half>)
declare <4 x half> @llvm.minimum.v4f16(<4 x half>, <4 x half>)
declare double @llvm.minimum.f64(double, double)
declare <2 x double> @llvm.minimum.v2f64(<2 x double>, <2 x double>)
declare <4 x double> @llvm.minimum.v4f64(<4 x double>, <4 x double>)
;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; GFX12-GISEL: {{.*}}
; GFX12-SDAG: {{.*}}