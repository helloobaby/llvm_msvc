; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 4
; RUN: opt < %s -S -passes=licm | FileCheck %s

; See https://discourse.llvm.org/t/rfc-dont-merge-memory-locations-in-aliassettracker/73336
; pairwise TBAA indicates NoAlias of load/store ptr at %s with store i32 at %0
; yet LICM fails to promote load/store ptr %s out of the loop

define void @_Z4testP1S(ptr %s) {
; CHECK-LABEL: define void @_Z4testP1S(
; CHECK-SAME: ptr [[S:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.cond.cleanup:
; CHECK-NEXT:    ret void
; CHECK:       for.body:
; CHECK-NEXT:    [[I_05:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ [[INC:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[TMP0:%.*]] = load ptr, ptr [[S]], align 4, !tbaa [[TBAA0:![0-9]+]]
; CHECK-NEXT:    store i32 [[I_05]], ptr [[TMP0]], align 4, !tbaa [[TBAA5:![0-9]+]]
; CHECK-NEXT:    [[ADD_PTR_I:%.*]] = getelementptr inbounds i32, ptr [[TMP0]], i32 1
; CHECK-NEXT:    store ptr [[ADD_PTR_I]], ptr [[S]], align 4, !tbaa [[TBAA7:![0-9]+]]
; CHECK-NEXT:    [[INC]] = add nuw nsw i32 [[I_05]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i32 [[INC]], 100
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[FOR_COND_CLEANUP:%.*]], label [[FOR_BODY]]
;
entry:
  br label %for.body

for.cond.cleanup:                                 ; preds = %for.body
  ret void

for.body:                                         ; preds = %entry, %for.body
  %i.05 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %0 = load ptr, ptr %s, align 4, !tbaa !0
  store i32 %i.05, ptr %0, align 4, !tbaa !5
  %add.ptr.i = getelementptr inbounds i32, ptr %0, i32 1
  store ptr %add.ptr.i, ptr %s, align 4, !tbaa !7
  %inc = add nuw nsw i32 %i.05, 1
  %exitcond.not = icmp eq i32 %inc, 100
  br i1 %exitcond.not, label %for.cond.cleanup, label %for.body
}

!0 = !{!1, !2, i64 0}
!1 = !{!"_ZTS1S", !2, i64 0}
!2 = !{!"any pointer", !3, i64 0}
!3 = !{!"omnipotent char", !4, i64 0}
!4 = !{!"Simple C++ TBAA"}
!5 = !{!6, !6, i64 0}
!6 = !{!"int", !3, i64 0}
!7 = !{!2, !2, i64 0}
;.
; CHECK: [[TBAA0]] = !{[[META1:![0-9]+]], [[META2:![0-9]+]], i64 0}
; CHECK: [[META1]] = !{!"_ZTS1S", [[META2]], i64 0}
; CHECK: [[META2]] = !{!"any pointer", [[META3:![0-9]+]], i64 0}
; CHECK: [[META3]] = !{!"omnipotent char", [[META4:![0-9]+]], i64 0}
; CHECK: [[META4]] = !{!"Simple C++ TBAA"}
; CHECK: [[TBAA5]] = !{[[META6:![0-9]+]], [[META6]], i64 0}
; CHECK: [[META6]] = !{!"int", [[META3]], i64 0}
; CHECK: [[TBAA7]] = !{[[META2]], [[META2]], i64 0}
;.