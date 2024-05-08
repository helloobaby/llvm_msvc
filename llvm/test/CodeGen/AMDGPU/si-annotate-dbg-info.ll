; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 4
; RUN: opt -mtriple=amdgcn-- -S -structurizecfg -si-annotate-control-flow %s | FileCheck -check-prefix=OPT %s

define amdgpu_ps i32 @if_else(i32 %0) !dbg !5 {
; OPT-LABEL: define amdgpu_ps i32 @if_else(
; OPT-SAME: i32 [[TMP0:%.*]]) !dbg [[DBG5:![0-9]+]] {
; OPT-NEXT:    [[C:%.*]] = icmp ne i32 [[TMP0]], 0, !dbg [[DBG13:![0-9]+]]
; OPT-NEXT:    tail call void @llvm.dbg.value(metadata i1 [[C]], metadata [[META9:![0-9]+]], metadata !DIExpression()), !dbg [[DBG13]]
; OPT-NEXT:    [[TMP2:%.*]] = call { i1, i64 } @llvm.amdgcn.if.i64(i1 [[C]]), !dbg [[DBG14:![0-9]+]]
; OPT-NEXT:    [[TMP3:%.*]] = extractvalue { i1, i64 } [[TMP2]], 0, !dbg [[DBG14]]
; OPT-NEXT:    [[TMP4:%.*]] = extractvalue { i1, i64 } [[TMP2]], 1, !dbg [[DBG14]]
; OPT-NEXT:    br i1 [[TMP3]], label [[FALSE:%.*]], label [[FLOW:%.*]], !dbg [[DBG14]]
; OPT:       Flow:
; OPT-NEXT:    [[TMP5:%.*]] = phi i32 [ 33, [[FALSE]] ], [ undef, [[TMP1:%.*]] ]
; OPT-NEXT:    [[TMP6:%.*]] = call { i1, i64 } @llvm.amdgcn.else.i64.i64(i64 [[TMP4]]), !dbg [[DBG14]]
; OPT-NEXT:    [[TMP7:%.*]] = extractvalue { i1, i64 } [[TMP6]], 0, !dbg [[DBG14]]
; OPT-NEXT:    [[TMP8:%.*]] = extractvalue { i1, i64 } [[TMP6]], 1, !dbg [[DBG14]]
; OPT-NEXT:    br i1 [[TMP7]], label [[TRUE:%.*]], label [[EXIT:%.*]], !dbg [[DBG14]]
; OPT:       true:
; OPT-NEXT:    br label [[EXIT]], !dbg [[DBG15:![0-9]+]]
; OPT:       false:
; OPT-NEXT:    br label [[FLOW]], !dbg [[DBG16:![0-9]+]]
; OPT:       exit:
; OPT-NEXT:    [[RET:%.*]] = phi i32 [ [[TMP5]], [[FLOW]] ], [ 42, [[TRUE]] ], !dbg [[DBG17:![0-9]+]]
; OPT-NEXT:    call void @llvm.amdgcn.end.cf.i64(i64 [[TMP8]]), !dbg [[DBG18:![0-9]+]]
; OPT-NEXT:    tail call void @llvm.dbg.value(metadata i32 [[RET]], metadata [[META11:![0-9]+]], metadata !DIExpression()), !dbg [[DBG17]]
; OPT-NEXT:    ret i32 [[RET]], !dbg [[DBG18]]
;
  %c = icmp eq i32 %0, 0, !dbg !13
  tail call void @llvm.dbg.value(metadata i1 %c, metadata !9, metadata !DIExpression()), !dbg !13
  br i1 %c, label %true, label %false, !dbg !14

true:                                             ; preds = %1
  br label %exit, !dbg !15

false:                                            ; preds = %1
  br label %exit, !dbg !16

exit:                                             ; preds = %false, %true
  %ret = phi i32 [ 42, %true ], [ 33, %false ], !dbg !17
  tail call void @llvm.dbg.value(metadata i32 %ret, metadata !11, metadata !DIExpression()), !dbg !17
  ret i32 %ret, !dbg !18
}

define amdgpu_ps void @loop_if_break(i32 %n) !dbg !19 {
; OPT-LABEL: define amdgpu_ps void @loop_if_break(
; OPT-SAME: i32 [[N:%.*]]) !dbg [[DBG19:![0-9]+]] {
; OPT-NEXT:  entry:
; OPT-NEXT:    br label [[LOOP:%.*]], !dbg [[DBG24:![0-9]+]]
; OPT:       loop:
; OPT-NEXT:    [[PHI_BROKEN:%.*]] = phi i64 [ [[TMP5:%.*]], [[FLOW:%.*]] ], [ 0, [[ENTRY:%.*]] ]
; OPT-NEXT:    [[I:%.*]] = phi i32 [ [[N]], [[ENTRY]] ], [ [[TMP3:%.*]], [[FLOW]] ], !dbg [[DBG25:![0-9]+]]
; OPT-NEXT:    tail call void @llvm.dbg.value(metadata i32 [[I]], metadata [[META21:![0-9]+]], metadata !DIExpression()), !dbg [[DBG25]]
; OPT-NEXT:    [[C:%.*]] = icmp ugt i32 [[I]], 0, !dbg [[DBG26:![0-9]+]]
; OPT-NEXT:    tail call void @llvm.dbg.value(metadata i1 [[C]], metadata [[META22:![0-9]+]], metadata !DIExpression()), !dbg [[DBG26]]
; OPT-NEXT:    [[TMP0:%.*]] = call { i1, i64 } @llvm.amdgcn.if.i64(i1 [[C]]), !dbg [[DBG27:![0-9]+]]
; OPT-NEXT:    [[TMP1:%.*]] = extractvalue { i1, i64 } [[TMP0]], 0, !dbg [[DBG27]]
; OPT-NEXT:    [[TMP2:%.*]] = extractvalue { i1, i64 } [[TMP0]], 1, !dbg [[DBG27]]
; OPT-NEXT:    br i1 [[TMP1]], label [[LOOP_BODY:%.*]], label [[FLOW]], !dbg [[DBG27]]
; OPT:       loop_body:
; OPT-NEXT:    [[I_NEXT:%.*]] = sub i32 [[I]], 1, !dbg [[DBG28:![0-9]+]]
; OPT-NEXT:    tail call void @llvm.dbg.value(metadata i32 [[I_NEXT]], metadata [[META23:![0-9]+]], metadata !DIExpression()), !dbg [[DBG28]]
; OPT-NEXT:    br label [[FLOW]], !dbg [[DBG29:![0-9]+]]
; OPT:       Flow:
; OPT-NEXT:    [[TMP3]] = phi i32 [ [[I_NEXT]], [[LOOP_BODY]] ], [ undef, [[LOOP]] ]
; OPT-NEXT:    [[TMP4:%.*]] = phi i1 [ false, [[LOOP_BODY]] ], [ true, [[LOOP]] ]
; OPT-NEXT:    call void @llvm.amdgcn.end.cf.i64(i64 [[TMP2]]), !dbg [[DBG27]]
; OPT-NEXT:    [[TMP5]] = call i64 @llvm.amdgcn.if.break.i64(i1 [[TMP4]], i64 [[PHI_BROKEN]]), !dbg [[DBG27]]
; OPT-NEXT:    [[TMP6:%.*]] = call i1 @llvm.amdgcn.loop.i64(i64 [[TMP5]]), !dbg [[DBG27]]
; OPT-NEXT:    br i1 [[TMP6]], label [[EXIT:%.*]], label [[LOOP]], !dbg [[DBG27]]
; OPT:       exit:
; OPT-NEXT:    call void @llvm.amdgcn.end.cf.i64(i64 [[TMP5]]), !dbg [[DBG30:![0-9]+]]
; OPT-NEXT:    ret void, !dbg [[DBG30]]
;
entry:
  br label %loop, !dbg !24

loop:                                             ; preds = %loop_body, %entry
  %i = phi i32 [ %n, %entry ], [ %i.next, %loop_body ], !dbg !25
  tail call void @llvm.dbg.value(metadata i32 %i, metadata !21, metadata !DIExpression()), !dbg !25
  %c = icmp ugt i32 %i, 0, !dbg !26
  tail call void @llvm.dbg.value(metadata i1 %c, metadata !22, metadata !DIExpression()), !dbg !26
  br i1 %c, label %loop_body, label %exit, !dbg !27

loop_body:                                        ; preds = %loop
  %i.next = sub i32 %i, 1, !dbg !28
  tail call void @llvm.dbg.value(metadata i32 %i.next, metadata !23, metadata !DIExpression()), !dbg !28
  br label %loop, !dbg !29

exit:                                             ; preds = %loop
  ret void, !dbg !30
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.value(metadata, metadata, metadata) #0

attributes #0 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!0}
!llvm.debugify = !{!2, !3}
!llvm.module.flags = !{!4}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "debugify", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "../../../test/CodeGen/AMDGPU/si-annotate-dbg-info.ll", directory: "/")
!2 = !{i32 13}
!3 = !{i32 5}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = distinct !DISubprogram(name: "if_else", linkageName: "if_else", scope: null, file: !1, line: 1, type: !6, scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !8)
!6 = !DISubroutineType(types: !7)
!7 = !{}
!8 = !{!9, !11}
!9 = !DILocalVariable(name: "1", scope: !5, file: !1, line: 1, type: !10)
!10 = !DIBasicType(name: "ty8", size: 8, encoding: DW_ATE_unsigned)
!11 = !DILocalVariable(name: "2", scope: !5, file: !1, line: 5, type: !12)
!12 = !DIBasicType(name: "ty32", size: 32, encoding: DW_ATE_unsigned)
!13 = !DILocation(line: 1, column: 1, scope: !5)
!14 = !DILocation(line: 2, column: 1, scope: !5)
!15 = !DILocation(line: 3, column: 1, scope: !5)
!16 = !DILocation(line: 4, column: 1, scope: !5)
!17 = !DILocation(line: 5, column: 1, scope: !5)
!18 = !DILocation(line: 6, column: 1, scope: !5)
!19 = distinct !DISubprogram(name: "loop_if_break", linkageName: "loop_if_break", scope: null, file: !1, line: 7, type: !6, scopeLine: 7, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !20)
!20 = !{!21, !22, !23}
!21 = !DILocalVariable(name: "3", scope: !19, file: !1, line: 8, type: !12)
!22 = !DILocalVariable(name: "4", scope: !19, file: !1, line: 9, type: !10)
!23 = !DILocalVariable(name: "5", scope: !19, file: !1, line: 11, type: !12)
!24 = !DILocation(line: 7, column: 1, scope: !19)
!25 = !DILocation(line: 8, column: 1, scope: !19)
!26 = !DILocation(line: 9, column: 1, scope: !19)
!27 = !DILocation(line: 10, column: 1, scope: !19)
!28 = !DILocation(line: 11, column: 1, scope: !19)
!29 = !DILocation(line: 12, column: 1, scope: !19)
!30 = !DILocation(line: 13, column: 1, scope: !19)
;.
; OPT: [[META0:![0-9]+]] = distinct !DICompileUnit(language: DW_LANG_C, file: [[META1:![0-9]+]], producer: "debugify", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
; OPT: [[META1]] = !DIFile(filename: "../../../test/CodeGen/AMDGPU/si-annotate-dbg-info.ll", directory: {{.*}})
; OPT: [[DBG5]] = distinct !DISubprogram(name: "if_else", linkageName: "if_else", scope: null, file: [[META1]], line: 1, type: [[META6:![0-9]+]], scopeLine: 1, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: [[META0]], retainedNodes: [[META8:![0-9]+]])
; OPT: [[META6]] = !DISubroutineType(types: [[META7:![0-9]+]])
; OPT: [[META7]] = !{}
; OPT: [[META8]] = !{[[META9]], [[META11]]}
; OPT: [[META9]] = !DILocalVariable(name: "1", scope: [[DBG5]], file: [[META1]], line: 1, type: [[META10:![0-9]+]])
; OPT: [[META10]] = !DIBasicType(name: "ty8", size: 8, encoding: DW_ATE_unsigned)
; OPT: [[META11]] = !DILocalVariable(name: "2", scope: [[DBG5]], file: [[META1]], line: 5, type: [[META12:![0-9]+]])
; OPT: [[META12]] = !DIBasicType(name: "ty32", size: 32, encoding: DW_ATE_unsigned)
; OPT: [[DBG13]] = !DILocation(line: 1, column: 1, scope: [[DBG5]])
; OPT: [[DBG14]] = !DILocation(line: 2, column: 1, scope: [[DBG5]])
; OPT: [[DBG15]] = !DILocation(line: 3, column: 1, scope: [[DBG5]])
; OPT: [[DBG16]] = !DILocation(line: 4, column: 1, scope: [[DBG5]])
; OPT: [[DBG17]] = !DILocation(line: 5, column: 1, scope: [[DBG5]])
; OPT: [[DBG18]] = !DILocation(line: 6, column: 1, scope: [[DBG5]])
; OPT: [[DBG19]] = distinct !DISubprogram(name: "loop_if_break", linkageName: "loop_if_break", scope: null, file: [[META1]], line: 7, type: [[META6]], scopeLine: 7, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: [[META0]], retainedNodes: [[META20:![0-9]+]])
; OPT: [[META20]] = !{[[META21]], [[META22]], [[META23]]}
; OPT: [[META21]] = !DILocalVariable(name: "3", scope: [[DBG19]], file: [[META1]], line: 8, type: [[META12]])
; OPT: [[META22]] = !DILocalVariable(name: "4", scope: [[DBG19]], file: [[META1]], line: 9, type: [[META10]])
; OPT: [[META23]] = !DILocalVariable(name: "5", scope: [[DBG19]], file: [[META1]], line: 11, type: [[META12]])
; OPT: [[DBG24]] = !DILocation(line: 7, column: 1, scope: [[DBG19]])
; OPT: [[DBG25]] = !DILocation(line: 8, column: 1, scope: [[DBG19]])
; OPT: [[DBG26]] = !DILocation(line: 9, column: 1, scope: [[DBG19]])
; OPT: [[DBG27]] = !DILocation(line: 10, column: 1, scope: [[DBG19]])
; OPT: [[DBG28]] = !DILocation(line: 11, column: 1, scope: [[DBG19]])
; OPT: [[DBG29]] = !DILocation(line: 12, column: 1, scope: [[DBG19]])
; OPT: [[DBG30]] = !DILocation(line: 13, column: 1, scope: [[DBG19]])
;.