; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -global-isel=1 -march=amdgcn -mcpu=gfx1100 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX11,GISEL11 %s
; RUN: llc -global-isel=0 -march=amdgcn -mcpu=gfx1100 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX11,DAGISEL11 %s
; RUN: llc -global-isel=1 -march=amdgcn -mcpu=gfx1030 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX10,GISEL10 %s
; RUN: llc -global-isel=0 -march=amdgcn -mcpu=gfx1030 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX10,DAGISEL10 %s
; RUN: llc -global-isel=1 -march=amdgcn -mcpu=gfx1100 -mattr=+wavefrontsize64 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX11_W64,GISEL11_W64 %s
; RUN: llc -global-isel=0 -march=amdgcn -mcpu=gfx1100 -mattr=+wavefrontsize64 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX11_W64,DAGISEL11_W64 %s
; RUN: llc -global-isel=1 -march=amdgcn -mcpu=gfx1030 -mattr=+wavefrontsize64 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX10_W64,GISEL10_W64 %s
; RUN: llc -global-isel=0 -march=amdgcn -mcpu=gfx1030 -mattr=+wavefrontsize64 -verify-machineinstrs < %s | FileCheck --check-prefixes=GFX10_W64,DAGISEL10_W64 %s

define amdgpu_cs_chain void @set_inactive_chain_arg(ptr addrspace(1) %out, i32 %inactive, i32 %active) {
; GFX11-LABEL: set_inactive_chain_arg:
; GFX11:       ; %bb.0:
; GFX11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11-NEXT:    v_mov_b32_e32 v0, v11
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    v_mov_b32_e32 v0, v10
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    global_store_b32 v[8:9], v0, off
; GFX11-NEXT:    s_endpgm
;
; GFX10-LABEL: set_inactive_chain_arg:
; GFX10:       ; %bb.0:
; GFX10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10-NEXT:    v_mov_b32_e32 v0, v11
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    v_mov_b32_e32 v0, v10
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    global_store_dword v[8:9], v0, off
; GFX10-NEXT:    s_endpgm
;
; GFX11_W64-LABEL: set_inactive_chain_arg:
; GFX11_W64:       ; %bb.0:
; GFX11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v11
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    global_store_b32 v[8:9], v0, off
; GFX11_W64-NEXT:    s_endpgm
;
; GFX10_W64-LABEL: set_inactive_chain_arg:
; GFX10_W64:       ; %bb.0:
; GFX10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v11
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    global_store_dword v[8:9], v0, off
; GFX10_W64-NEXT:    s_endpgm
  %tmp = call i32 @llvm.amdgcn.set.inactive.chain.arg.i32(i32 %active, i32 %inactive) #0
  store i32 %tmp, ptr addrspace(1) %out
  ret void
}

define amdgpu_cs_chain void @set_inactive_chain_arg_64(ptr addrspace(1) %out, i64 %inactive, i64 %active) {
; GFX11-LABEL: set_inactive_chain_arg_64:
; GFX11:       ; %bb.0:
; GFX11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11-NEXT:    v_mov_b32_e32 v0, v12
; GFX11-NEXT:    v_mov_b32_e32 v1, v13
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    v_mov_b32_e32 v0, v10
; GFX11-NEXT:    v_mov_b32_e32 v1, v11
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    global_store_b64 v[8:9], v[0:1], off
; GFX11-NEXT:    s_endpgm
;
; GFX10-LABEL: set_inactive_chain_arg_64:
; GFX10:       ; %bb.0:
; GFX10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10-NEXT:    v_mov_b32_e32 v0, v12
; GFX10-NEXT:    v_mov_b32_e32 v1, v13
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    v_mov_b32_e32 v0, v10
; GFX10-NEXT:    v_mov_b32_e32 v1, v11
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    global_store_dwordx2 v[8:9], v[0:1], off
; GFX10-NEXT:    s_endpgm
;
; GFX11_W64-LABEL: set_inactive_chain_arg_64:
; GFX11_W64:       ; %bb.0:
; GFX11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v12
; GFX11_W64-NEXT:    v_mov_b32_e32 v1, v13
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX11_W64-NEXT:    v_mov_b32_e32 v1, v11
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    global_store_b64 v[8:9], v[0:1], off
; GFX11_W64-NEXT:    s_endpgm
;
; GFX10_W64-LABEL: set_inactive_chain_arg_64:
; GFX10_W64:       ; %bb.0:
; GFX10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v12
; GFX10_W64-NEXT:    v_mov_b32_e32 v1, v13
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX10_W64-NEXT:    v_mov_b32_e32 v1, v11
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    global_store_dwordx2 v[8:9], v[0:1], off
; GFX10_W64-NEXT:    s_endpgm
  %tmp = call i64 @llvm.amdgcn.set.inactive.chain.arg.i64(i64 %active, i64 %inactive) #0
  store i64 %tmp, ptr addrspace(1) %out
  ret void
}

define amdgpu_cs_chain void @set_inactive_chain_arg_dpp(ptr addrspace(1) %out, i32 %inactive, i32 %active) {
; GFX11-LABEL: set_inactive_chain_arg_dpp:
; GFX11:       ; %bb.0:
; GFX11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11-NEXT:    s_or_saveexec_b32 s0, -1
; GFX11-NEXT:    v_mov_b32_e32 v0, v10
; GFX11-NEXT:    s_mov_b32 exec_lo, s0
; GFX11-NEXT:    v_mov_b32_e32 v0, v11
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    s_delay_alu instid0(VALU_DEP_1) | instskip(SKIP_3) | instid1(VALU_DEP_1)
; GFX11-NEXT:    v_mov_b32_e32 v0, v0
; GFX11-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX11-NEXT:    s_or_saveexec_b32 s0, -1
; GFX11-NEXT:    v_mov_b32_e32 v1, 0
; GFX11-NEXT:    v_mov_b32_dpp v1, v0 row_xmask:1 row_mask:0xf bank_mask:0xf
; GFX11-NEXT:    s_mov_b32 exec_lo, s0
; GFX11-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GFX11-NEXT:    v_mov_b32_e32 v2, v1
; GFX11-NEXT:    global_store_b32 v[8:9], v2, off
; GFX11-NEXT:    s_endpgm
;
; GFX10-LABEL: set_inactive_chain_arg_dpp:
; GFX10:       ; %bb.0:
; GFX10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10-NEXT:    s_or_saveexec_b32 s0, -1
; GFX10-NEXT:    v_mov_b32_e32 v0, v10
; GFX10-NEXT:    s_mov_b32 exec_lo, s0
; GFX10-NEXT:    v_mov_b32_e32 v0, v11
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    v_mov_b32_e32 v0, v0
; GFX10-NEXT:    s_not_b32 exec_lo, exec_lo
; GFX10-NEXT:    s_or_saveexec_b32 s0, -1
; GFX10-NEXT:    v_mov_b32_e32 v1, 0
; GFX10-NEXT:    v_mov_b32_dpp v1, v0 row_xmask:1 row_mask:0xf bank_mask:0xf
; GFX10-NEXT:    s_mov_b32 exec_lo, s0
; GFX10-NEXT:    v_mov_b32_e32 v2, v1
; GFX10-NEXT:    global_store_dword v[8:9], v2, off
; GFX10-NEXT:    s_endpgm
;
; GFX11_W64-LABEL: set_inactive_chain_arg_dpp:
; GFX11_W64:       ; %bb.0:
; GFX11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v11
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GFX11_W64-NEXT:    v_mov_b32_e32 v0, v0
; GFX11_W64-NEXT:    s_not_b64 exec, exec
; GFX11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GFX11_W64-NEXT:    v_mov_b32_e32 v1, 0
; GFX11_W64-NEXT:    s_waitcnt_depctr 0xfff
; GFX11_W64-NEXT:    v_mov_b32_dpp v1, v0 row_xmask:1 row_mask:0xf bank_mask:0xf
; GFX11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GFX11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GFX11_W64-NEXT:    v_mov_b32_e32 v2, v1
; GFX11_W64-NEXT:    global_store_b32 v[8:9], v2, off
; GFX11_W64-NEXT:    s_endpgm
;
; GFX10_W64-LABEL: set_inactive_chain_arg_dpp:
; GFX10_W64:       ; %bb.0:
; GFX10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GFX10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v10
; GFX10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v11
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    v_mov_b32_e32 v0, v0
; GFX10_W64-NEXT:    s_not_b64 exec, exec
; GFX10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GFX10_W64-NEXT:    v_mov_b32_e32 v1, 0
; GFX10_W64-NEXT:    v_mov_b32_dpp v1, v0 row_xmask:1 row_mask:0xf bank_mask:0xf
; GFX10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GFX10_W64-NEXT:    v_mov_b32_e32 v2, v1
; GFX10_W64-NEXT:    global_store_dword v[8:9], v2, off
; GFX10_W64-NEXT:    s_endpgm
  %tmp = call i32 @llvm.amdgcn.set.inactive.chain.arg.i32(i32 %active, i32 %inactive) #0
  %dpp = call i32 @llvm.amdgcn.update.dpp.i32(i32 0, i32 %tmp, i32 353, i32 15, i32 15, i1 false)
  %wwm = call i32 @llvm.amdgcn.strict.wwm.i32(i32 %dpp)
  store i32 %wwm, ptr addrspace(1) %out
  ret void
}

; Make sure that if we need to use the register for %inactive for something else (in this case a call),
; we save its inactive lanes for later use in set.inactive.chain.arg.
define amdgpu_cs_chain void @set_inactive_chain_arg_call(ptr addrspace(1) %out, i32 %inactive, i32 %active) {
; GISEL11-LABEL: set_inactive_chain_arg_call:
; GISEL11:       ; %bb.0:
; GISEL11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL11-NEXT:    s_mov_b32 s32, 0
; GISEL11-NEXT:    v_dual_mov_b32 v41, v8 :: v_dual_mov_b32 v42, v9
; GISEL11-NEXT:    s_or_saveexec_b32 s0, -1
; GISEL11-NEXT:    v_mov_b32_e32 v40, v10
; GISEL11-NEXT:    s_mov_b32 exec_lo, s0
; GISEL11-NEXT:    s_getpc_b64 s[0:1]
; GISEL11-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL11-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL11-NEXT:    v_dual_mov_b32 v43, v11 :: v_dual_mov_b32 v0, 0
; GISEL11-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; GISEL11-NEXT:    v_dual_mov_b32 v1, 0 :: v_dual_mov_b32 v2, 0
; GISEL11-NEXT:    v_dual_mov_b32 v3, 0 :: v_dual_mov_b32 v4, 0
; GISEL11-NEXT:    v_dual_mov_b32 v5, 0 :: v_dual_mov_b32 v6, 0
; GISEL11-NEXT:    v_dual_mov_b32 v7, 0 :: v_dual_mov_b32 v8, 0
; GISEL11-NEXT:    v_dual_mov_b32 v9, 0 :: v_dual_mov_b32 v10, 0
; GISEL11-NEXT:    v_mov_b32_e32 v11, 0
; GISEL11-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL11-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; GISEL11-NEXT:    v_mov_b32_e32 v12, v43
; GISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL11-NEXT:    v_mov_b32_e32 v12, v40
; GISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL11-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GISEL11-NEXT:    v_mov_b32_e32 v0, v12
; GISEL11-NEXT:    global_store_b32 v[41:42], v0, off
; GISEL11-NEXT:    s_endpgm
;
; DAGISEL11-LABEL: set_inactive_chain_arg_call:
; DAGISEL11:       ; %bb.0:
; DAGISEL11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL11-NEXT:    s_mov_b32 s32, 0
; DAGISEL11-NEXT:    v_mov_b32_e32 v43, v11
; DAGISEL11-NEXT:    s_or_saveexec_b32 s0, -1
; DAGISEL11-NEXT:    v_mov_b32_e32 v40, v10
; DAGISEL11-NEXT:    s_mov_b32 exec_lo, s0
; DAGISEL11-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL11-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL11-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL11-NEXT:    v_dual_mov_b32 v42, v9 :: v_dual_mov_b32 v41, v8
; DAGISEL11-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; DAGISEL11-NEXT:    v_dual_mov_b32 v0, 0 :: v_dual_mov_b32 v1, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v2, 0 :: v_dual_mov_b32 v3, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v4, 0 :: v_dual_mov_b32 v5, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v6, 0 :: v_dual_mov_b32 v7, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v8, 0 :: v_dual_mov_b32 v9, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v10, 0 :: v_dual_mov_b32 v11, 0
; DAGISEL11-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL11-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; DAGISEL11-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL11-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL11-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; DAGISEL11-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL11-NEXT:    global_store_b32 v[41:42], v0, off
; DAGISEL11-NEXT:    s_endpgm
;
; GISEL10-LABEL: set_inactive_chain_arg_call:
; GISEL10:       ; %bb.0:
; GISEL10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL10-NEXT:    s_mov_b32 s32, 0
; GISEL10-NEXT:    v_mov_b32_e32 v41, v8
; GISEL10-NEXT:    v_mov_b32_e32 v42, v9
; GISEL10-NEXT:    s_or_saveexec_b32 s0, -1
; GISEL10-NEXT:    v_mov_b32_e32 v40, v10
; GISEL10-NEXT:    s_mov_b32 exec_lo, s0
; GISEL10-NEXT:    s_getpc_b64 s[0:1]
; GISEL10-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL10-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL10-NEXT:    v_mov_b32_e32 v43, v11
; GISEL10-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; GISEL10-NEXT:    v_mov_b32_e32 v0, 0
; GISEL10-NEXT:    v_mov_b32_e32 v1, 0
; GISEL10-NEXT:    v_mov_b32_e32 v2, 0
; GISEL10-NEXT:    v_mov_b32_e32 v3, 0
; GISEL10-NEXT:    v_mov_b32_e32 v4, 0
; GISEL10-NEXT:    v_mov_b32_e32 v5, 0
; GISEL10-NEXT:    v_mov_b32_e32 v6, 0
; GISEL10-NEXT:    v_mov_b32_e32 v7, 0
; GISEL10-NEXT:    v_mov_b32_e32 v8, 0
; GISEL10-NEXT:    v_mov_b32_e32 v9, 0
; GISEL10-NEXT:    v_mov_b32_e32 v10, 0
; GISEL10-NEXT:    v_mov_b32_e32 v11, 0
; GISEL10-NEXT:    s_mov_b64 s[0:1], s[48:49]
; GISEL10-NEXT:    s_mov_b64 s[2:3], s[50:51]
; GISEL10-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL10-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; GISEL10-NEXT:    v_mov_b32_e32 v12, v43
; GISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL10-NEXT:    v_mov_b32_e32 v12, v40
; GISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL10-NEXT:    v_mov_b32_e32 v0, v12
; GISEL10-NEXT:    global_store_dword v[41:42], v0, off
; GISEL10-NEXT:    s_endpgm
;
; DAGISEL10-LABEL: set_inactive_chain_arg_call:
; DAGISEL10:       ; %bb.0:
; DAGISEL10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL10-NEXT:    s_mov_b32 s32, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v43, v11
; DAGISEL10-NEXT:    s_or_saveexec_b32 s0, -1
; DAGISEL10-NEXT:    v_mov_b32_e32 v40, v10
; DAGISEL10-NEXT:    s_mov_b32 exec_lo, s0
; DAGISEL10-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL10-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL10-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL10-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL10-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; DAGISEL10-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL10-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL10-NEXT:    s_mov_b64 s[0:1], s[48:49]
; DAGISEL10-NEXT:    s_mov_b64 s[2:3], s[50:51]
; DAGISEL10-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL10-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; DAGISEL10-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL10-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL10-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL10-NEXT:    global_store_dword v[41:42], v0, off
; DAGISEL10-NEXT:    s_endpgm
;
; GISEL11_W64-LABEL: set_inactive_chain_arg_call:
; GISEL11_W64:       ; %bb.0:
; GISEL11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL11_W64-NEXT:    s_mov_b32 s32, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v41, v8
; GISEL11_W64-NEXT:    v_mov_b32_e32 v42, v9
; GISEL11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GISEL11_W64-NEXT:    v_mov_b32_e32 v40, v10
; GISEL11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GISEL11_W64-NEXT:    s_getpc_b64 s[0:1]
; GISEL11_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL11_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL11_W64-NEXT:    v_mov_b32_e32 v43, v11
; GISEL11_W64-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v0, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v1, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v2, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v3, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v4, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v5, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v6, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v7, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v8, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v9, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v10, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v11, 0
; GISEL11_W64-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL11_W64-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; GISEL11_W64-NEXT:    v_mov_b32_e32 v12, v43
; GISEL11_W64-NEXT:    s_not_b64 exec, exec
; GISEL11_W64-NEXT:    v_mov_b32_e32 v12, v40
; GISEL11_W64-NEXT:    s_not_b64 exec, exec
; GISEL11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GISEL11_W64-NEXT:    v_mov_b32_e32 v0, v12
; GISEL11_W64-NEXT:    global_store_b32 v[41:42], v0, off
; GISEL11_W64-NEXT:    s_endpgm
;
; DAGISEL11_W64-LABEL: set_inactive_chain_arg_call:
; DAGISEL11_W64:       ; %bb.0:
; DAGISEL11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL11_W64-NEXT:    s_mov_b32 s32, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v43, v11
; DAGISEL11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v40, v10
; DAGISEL11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; DAGISEL11_W64-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL11_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL11_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL11_W64-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL11_W64-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL11_W64-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL11_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL11_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL11_W64-NEXT:    global_store_b32 v[41:42], v0, off
; DAGISEL11_W64-NEXT:    s_endpgm
;
; GISEL10_W64-LABEL: set_inactive_chain_arg_call:
; GISEL10_W64:       ; %bb.0:
; GISEL10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL10_W64-NEXT:    s_mov_b32 s32, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v41, v8
; GISEL10_W64-NEXT:    v_mov_b32_e32 v42, v9
; GISEL10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GISEL10_W64-NEXT:    v_mov_b32_e32 v40, v10
; GISEL10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GISEL10_W64-NEXT:    s_getpc_b64 s[0:1]
; GISEL10_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL10_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL10_W64-NEXT:    v_mov_b32_e32 v43, v11
; GISEL10_W64-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v0, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v1, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v2, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v3, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v4, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v5, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v6, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v7, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v8, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v9, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v10, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v11, 0
; GISEL10_W64-NEXT:    s_mov_b64 s[0:1], s[48:49]
; GISEL10_W64-NEXT:    s_mov_b64 s[2:3], s[50:51]
; GISEL10_W64-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL10_W64-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; GISEL10_W64-NEXT:    v_mov_b32_e32 v12, v43
; GISEL10_W64-NEXT:    s_not_b64 exec, exec
; GISEL10_W64-NEXT:    v_mov_b32_e32 v12, v40
; GISEL10_W64-NEXT:    s_not_b64 exec, exec
; GISEL10_W64-NEXT:    v_mov_b32_e32 v0, v12
; GISEL10_W64-NEXT:    global_store_dword v[41:42], v0, off
; GISEL10_W64-NEXT:    s_endpgm
;
; DAGISEL10_W64-LABEL: set_inactive_chain_arg_call:
; DAGISEL10_W64:       ; %bb.0:
; DAGISEL10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL10_W64-NEXT:    s_mov_b32 s32, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v43, v11
; DAGISEL10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v40, v10
; DAGISEL10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; DAGISEL10_W64-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL10_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL10_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL10_W64-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL10_W64-NEXT:    s_mov_b64 s[0:1], s[48:49]
; DAGISEL10_W64-NEXT:    s_mov_b64 s[2:3], s[50:51]
; DAGISEL10_W64-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL10_W64-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL10_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL10_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL10_W64-NEXT:    global_store_dword v[41:42], v0, off
; DAGISEL10_W64-NEXT:    s_endpgm
  call amdgpu_gfx void @gfx_callee(<12 x i32> zeroinitializer)
  %tmp = call i32 @llvm.amdgcn.set.inactive.chain.arg.i32(i32 %active, i32 %inactive) #0
  %wwm = call i32 @llvm.amdgcn.strict.wwm.i32(i32 %tmp)
  store i32 %wwm, ptr addrspace(1) %out
  ret void
}

; When lowering function arguments, SelectionDAG will put the COPY for the last argument first.
; This used to trigger a bug in si-wqm where the first COPY in the entry block was always skipped
; before entering a strict mode, meaning that we'd only copy the active lanes of the last VGPR
; argument, so we'd end up using arbitrary values for the inactive lanes.
define amdgpu_cs_chain void @set_inactive_chain_arg_last_vgpr(ptr addrspace(1) %out, i32 %active, i32 %inactive) {
; GISEL11-LABEL: set_inactive_chain_arg_last_vgpr:
; GISEL11:       ; %bb.0:
; GISEL11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL11-NEXT:    s_mov_b32 s32, 0
; GISEL11-NEXT:    v_dual_mov_b32 v41, v8 :: v_dual_mov_b32 v42, v9
; GISEL11-NEXT:    v_mov_b32_e32 v43, v10
; GISEL11-NEXT:    s_or_saveexec_b32 s0, -1
; GISEL11-NEXT:    v_mov_b32_e32 v40, v11
; GISEL11-NEXT:    s_mov_b32 exec_lo, s0
; GISEL11-NEXT:    s_getpc_b64 s[0:1]
; GISEL11-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL11-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL11-NEXT:    v_dual_mov_b32 v0, 0 :: v_dual_mov_b32 v1, 0
; GISEL11-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; GISEL11-NEXT:    v_dual_mov_b32 v2, 0 :: v_dual_mov_b32 v3, 0
; GISEL11-NEXT:    v_dual_mov_b32 v4, 0 :: v_dual_mov_b32 v5, 0
; GISEL11-NEXT:    v_dual_mov_b32 v6, 0 :: v_dual_mov_b32 v7, 0
; GISEL11-NEXT:    v_dual_mov_b32 v8, 0 :: v_dual_mov_b32 v9, 0
; GISEL11-NEXT:    v_dual_mov_b32 v10, 0 :: v_dual_mov_b32 v11, 0
; GISEL11-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL11-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; GISEL11-NEXT:    v_mov_b32_e32 v12, v43
; GISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL11-NEXT:    v_mov_b32_e32 v12, v40
; GISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL11-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GISEL11-NEXT:    v_mov_b32_e32 v0, v12
; GISEL11-NEXT:    global_store_b32 v[41:42], v0, off
; GISEL11-NEXT:    s_endpgm
;
; DAGISEL11-LABEL: set_inactive_chain_arg_last_vgpr:
; DAGISEL11:       ; %bb.0:
; DAGISEL11-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL11-NEXT:    s_mov_b32 s32, 0
; DAGISEL11-NEXT:    s_or_saveexec_b32 s0, -1
; DAGISEL11-NEXT:    v_mov_b32_e32 v40, v11
; DAGISEL11-NEXT:    s_mov_b32 exec_lo, s0
; DAGISEL11-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL11-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL11-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL11-NEXT:    v_dual_mov_b32 v43, v10 :: v_dual_mov_b32 v42, v9
; DAGISEL11-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; DAGISEL11-NEXT:    v_dual_mov_b32 v41, v8 :: v_dual_mov_b32 v0, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v1, 0 :: v_dual_mov_b32 v2, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v3, 0 :: v_dual_mov_b32 v4, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v5, 0 :: v_dual_mov_b32 v6, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v7, 0 :: v_dual_mov_b32 v8, 0
; DAGISEL11-NEXT:    v_dual_mov_b32 v9, 0 :: v_dual_mov_b32 v10, 0
; DAGISEL11-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL11-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL11-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; DAGISEL11-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL11-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL11-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL11-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; DAGISEL11-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL11-NEXT:    global_store_b32 v[41:42], v0, off
; DAGISEL11-NEXT:    s_endpgm
;
; GISEL10-LABEL: set_inactive_chain_arg_last_vgpr:
; GISEL10:       ; %bb.0:
; GISEL10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL10-NEXT:    s_mov_b32 s32, 0
; GISEL10-NEXT:    v_mov_b32_e32 v41, v8
; GISEL10-NEXT:    v_mov_b32_e32 v42, v9
; GISEL10-NEXT:    v_mov_b32_e32 v43, v10
; GISEL10-NEXT:    s_or_saveexec_b32 s0, -1
; GISEL10-NEXT:    v_mov_b32_e32 v40, v11
; GISEL10-NEXT:    s_mov_b32 exec_lo, s0
; GISEL10-NEXT:    s_getpc_b64 s[0:1]
; GISEL10-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL10-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL10-NEXT:    v_mov_b32_e32 v0, 0
; GISEL10-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; GISEL10-NEXT:    v_mov_b32_e32 v1, 0
; GISEL10-NEXT:    v_mov_b32_e32 v2, 0
; GISEL10-NEXT:    v_mov_b32_e32 v3, 0
; GISEL10-NEXT:    v_mov_b32_e32 v4, 0
; GISEL10-NEXT:    v_mov_b32_e32 v5, 0
; GISEL10-NEXT:    v_mov_b32_e32 v6, 0
; GISEL10-NEXT:    v_mov_b32_e32 v7, 0
; GISEL10-NEXT:    v_mov_b32_e32 v8, 0
; GISEL10-NEXT:    v_mov_b32_e32 v9, 0
; GISEL10-NEXT:    v_mov_b32_e32 v10, 0
; GISEL10-NEXT:    v_mov_b32_e32 v11, 0
; GISEL10-NEXT:    s_mov_b64 s[0:1], s[48:49]
; GISEL10-NEXT:    s_mov_b64 s[2:3], s[50:51]
; GISEL10-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL10-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; GISEL10-NEXT:    v_mov_b32_e32 v12, v43
; GISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL10-NEXT:    v_mov_b32_e32 v12, v40
; GISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; GISEL10-NEXT:    v_mov_b32_e32 v0, v12
; GISEL10-NEXT:    global_store_dword v[41:42], v0, off
; GISEL10-NEXT:    s_endpgm
;
; DAGISEL10-LABEL: set_inactive_chain_arg_last_vgpr:
; DAGISEL10:       ; %bb.0:
; DAGISEL10-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL10-NEXT:    s_mov_b32 s32, 0
; DAGISEL10-NEXT:    s_or_saveexec_b32 s0, -1
; DAGISEL10-NEXT:    v_mov_b32_e32 v40, v11
; DAGISEL10-NEXT:    s_mov_b32 exec_lo, s0
; DAGISEL10-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL10-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL10-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL10-NEXT:    v_mov_b32_e32 v43, v10
; DAGISEL10-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; DAGISEL10-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL10-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL10-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL10-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL10-NEXT:    s_mov_b64 s[0:1], s[48:49]
; DAGISEL10-NEXT:    s_mov_b64 s[2:3], s[50:51]
; DAGISEL10-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL10-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; DAGISEL10-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL10-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL10-NEXT:    s_not_b32 exec_lo, exec_lo
; DAGISEL10-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL10-NEXT:    global_store_dword v[41:42], v0, off
; DAGISEL10-NEXT:    s_endpgm
;
; GISEL11_W64-LABEL: set_inactive_chain_arg_last_vgpr:
; GISEL11_W64:       ; %bb.0:
; GISEL11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL11_W64-NEXT:    s_mov_b32 s32, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v41, v8
; GISEL11_W64-NEXT:    v_mov_b32_e32 v42, v9
; GISEL11_W64-NEXT:    v_mov_b32_e32 v43, v10
; GISEL11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GISEL11_W64-NEXT:    v_mov_b32_e32 v40, v11
; GISEL11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GISEL11_W64-NEXT:    s_getpc_b64 s[0:1]
; GISEL11_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL11_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL11_W64-NEXT:    v_mov_b32_e32 v0, 0
; GISEL11_W64-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v1, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v2, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v3, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v4, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v5, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v6, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v7, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v8, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v9, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v10, 0
; GISEL11_W64-NEXT:    v_mov_b32_e32 v11, 0
; GISEL11_W64-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL11_W64-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; GISEL11_W64-NEXT:    v_mov_b32_e32 v12, v43
; GISEL11_W64-NEXT:    s_not_b64 exec, exec
; GISEL11_W64-NEXT:    v_mov_b32_e32 v12, v40
; GISEL11_W64-NEXT:    s_not_b64 exec, exec
; GISEL11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; GISEL11_W64-NEXT:    v_mov_b32_e32 v0, v12
; GISEL11_W64-NEXT:    global_store_b32 v[41:42], v0, off
; GISEL11_W64-NEXT:    s_endpgm
;
; DAGISEL11_W64-LABEL: set_inactive_chain_arg_last_vgpr:
; DAGISEL11_W64:       ; %bb.0:
; DAGISEL11_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL11_W64-NEXT:    s_mov_b32 s32, 0
; DAGISEL11_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v40, v11
; DAGISEL11_W64-NEXT:    s_mov_b64 exec, s[0:1]
; DAGISEL11_W64-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL11_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL11_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v43, v10
; DAGISEL11_W64-NEXT:    s_load_b64 s[0:1], s[0:1], 0x0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL11_W64-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL11_W64-NEXT:    s_swappc_b64 s[30:31], s[0:1]
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL11_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL11_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL11_W64-NEXT:    s_delay_alu instid0(VALU_DEP_1)
; DAGISEL11_W64-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL11_W64-NEXT:    global_store_b32 v[41:42], v0, off
; DAGISEL11_W64-NEXT:    s_endpgm
;
; GISEL10_W64-LABEL: set_inactive_chain_arg_last_vgpr:
; GISEL10_W64:       ; %bb.0:
; GISEL10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; GISEL10_W64-NEXT:    s_mov_b32 s32, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v41, v8
; GISEL10_W64-NEXT:    v_mov_b32_e32 v42, v9
; GISEL10_W64-NEXT:    v_mov_b32_e32 v43, v10
; GISEL10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; GISEL10_W64-NEXT:    v_mov_b32_e32 v40, v11
; GISEL10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; GISEL10_W64-NEXT:    s_getpc_b64 s[0:1]
; GISEL10_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; GISEL10_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; GISEL10_W64-NEXT:    v_mov_b32_e32 v0, 0
; GISEL10_W64-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v1, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v2, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v3, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v4, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v5, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v6, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v7, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v8, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v9, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v10, 0
; GISEL10_W64-NEXT:    v_mov_b32_e32 v11, 0
; GISEL10_W64-NEXT:    s_mov_b64 s[0:1], s[48:49]
; GISEL10_W64-NEXT:    s_mov_b64 s[2:3], s[50:51]
; GISEL10_W64-NEXT:    s_waitcnt lgkmcnt(0)
; GISEL10_W64-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; GISEL10_W64-NEXT:    v_mov_b32_e32 v12, v43
; GISEL10_W64-NEXT:    s_not_b64 exec, exec
; GISEL10_W64-NEXT:    v_mov_b32_e32 v12, v40
; GISEL10_W64-NEXT:    s_not_b64 exec, exec
; GISEL10_W64-NEXT:    v_mov_b32_e32 v0, v12
; GISEL10_W64-NEXT:    global_store_dword v[41:42], v0, off
; GISEL10_W64-NEXT:    s_endpgm
;
; DAGISEL10_W64-LABEL: set_inactive_chain_arg_last_vgpr:
; DAGISEL10_W64:       ; %bb.0:
; DAGISEL10_W64-NEXT:    s_waitcnt vmcnt(0) expcnt(0) lgkmcnt(0)
; DAGISEL10_W64-NEXT:    s_mov_b32 s32, 0
; DAGISEL10_W64-NEXT:    s_or_saveexec_b64 s[0:1], -1
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v40, v11
; DAGISEL10_W64-NEXT:    s_mov_b64 exec, s[0:1]
; DAGISEL10_W64-NEXT:    s_getpc_b64 s[0:1]
; DAGISEL10_W64-NEXT:    s_add_u32 s0, s0, gfx_callee@gotpcrel32@lo+4
; DAGISEL10_W64-NEXT:    s_addc_u32 s1, s1, gfx_callee@gotpcrel32@hi+12
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v43, v10
; DAGISEL10_W64-NEXT:    s_load_dwordx2 s[4:5], s[0:1], 0x0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v42, v9
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v41, v8
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v0, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v1, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v2, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v3, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v4, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v5, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v6, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v7, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v8, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v9, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v10, 0
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v11, 0
; DAGISEL10_W64-NEXT:    s_mov_b64 s[0:1], s[48:49]
; DAGISEL10_W64-NEXT:    s_mov_b64 s[2:3], s[50:51]
; DAGISEL10_W64-NEXT:    s_waitcnt lgkmcnt(0)
; DAGISEL10_W64-NEXT:    s_swappc_b64 s[30:31], s[4:5]
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v12, v43
; DAGISEL10_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v12, v40
; DAGISEL10_W64-NEXT:    s_not_b64 exec, exec
; DAGISEL10_W64-NEXT:    v_mov_b32_e32 v0, v12
; DAGISEL10_W64-NEXT:    global_store_dword v[41:42], v0, off
; DAGISEL10_W64-NEXT:    s_endpgm
  call amdgpu_gfx void @gfx_callee(<12 x i32> zeroinitializer)
  %tmp = call i32 @llvm.amdgcn.set.inactive.chain.arg.i32(i32 %active, i32 %inactive) #0
  %wwm = call i32 @llvm.amdgcn.strict.wwm.i32(i32 %tmp)
  store i32 %wwm, ptr addrspace(1) %out
  ret void
}

declare i32 @llvm.amdgcn.set.inactive.chain.arg.i32(i32, i32) #0
declare i64 @llvm.amdgcn.set.inactive.chain.arg.i64(i64, i64) #0
declare i32 @llvm.amdgcn.update.dpp.i32(i32, i32, i32 immarg, i32 immarg, i32 immarg, i1 immarg)
declare i32 @llvm.amdgcn.strict.wwm.i32(i32)
declare amdgpu_gfx void @gfx_callee(<12 x i32>)

attributes #0 = { convergent readnone willreturn nocallback nofree}