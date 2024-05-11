; ModuleID = 'Substitution.cpp'
source_filename = "Substitution.cpp"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc19.29.30151"

%struct.test = type { i32, i32, i32 }

$llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53 = comdat any

@llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53 = linkonce_odr constant [25 x i8] c"Welcome to use llvm-msvc.", comdat
@llvm.used = appending global [1 x ptr] [ptr @llvm_msvc_marker_GV_fae0b27c451c728867a567e8c1bb4e53], section "llvm.metadata"

; Function Attrs: mustprogress noinline nounwind null_pointer_is_valid optnone uwtable
define dso_local void @"?f@@YA?A?<auto>@@XZ"(ptr noalias sret(%struct.test) align 4 %0) #0 {
  %2 = alloca ptr, align 8
  %3 = icmp ne i32 1, 287454020
  br i1 %3, label %4, label %8

4:                                                ; preds = %1
  store ptr %0, ptr %2, align 8
  %5 = getelementptr inbounds %struct.test, ptr %0, i32 0, i32 0
  store i32 1, ptr %5, align 4
  %6 = getelementptr inbounds %struct.test, ptr %0, i32 0, i32 1
  store i32 2, ptr %6, align 4
  %7 = getelementptr inbounds %struct.test, ptr %0, i32 0, i32 2
  store i32 3, ptr %7, align 4
  ret void

8:                                                ; preds = %1
  call void asm inteldialect "sub rsp,0x12345678", ""()
  ret void
}

; Function Attrs: mustprogress noinline norecurse nounwind null_pointer_is_valid optnone uwtable
define dso_local noundef i32 @main(i32 noundef %0, ptr noundef %1) #1 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca %struct.test, align 4
  %9 = alloca %struct.test, align 4
  %10 = icmp ne i32 1, 287454020
  br i1 %10, label %11, label %24

11:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  store ptr %1, ptr %4, align 8
  store i32 %0, ptr %5, align 4
  store i32 0, ptr %6, align 4
  %12 = load i32, ptr %6, align 4
  %13 = and i32 %12, 1
  %14 = mul i32 2, %13
  %15 = xor i32 %12, 1
  %16 = add i32 %15, %14
  store volatile i32 %16, ptr %7, align 4
  %17 = load volatile i32, ptr %7, align 4
  %18 = getelementptr inbounds %struct.test, ptr %8, i32 0, i32 1
  store i32 %17, ptr %18, align 4
  %19 = load i32, ptr %6, align 4
  %20 = getelementptr inbounds %struct.test, ptr %8, i32 0, i32 0
  store i32 %19, ptr %20, align 4
  %21 = getelementptr inbounds %struct.test, ptr %8, i32 0, i32 2
  store i32 0, ptr %21, align 4
  call void @"?f@@YA?A?<auto>@@XZ"(ptr sret(%struct.test) align 4 %9)
  %22 = getelementptr inbounds %struct.test, ptr %8, i32 0, i32 1
  %23 = load i32, ptr %22, align 4
  ret i32 %23

24:                                               ; preds = %2
  call void asm inteldialect "sub rsp,0x12345678", ""()
  ret i32 0
}

attributes #0 = { mustprogress noinline nounwind null_pointer_is_valid optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+crc32,+cx8,+fsgsbase,+fxsr,+invpcid,+mmx,+popcnt,+rtm,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+ssse3,+x87" "tune-cpu"="generic" }
attributes #1 = { mustprogress noinline norecurse nounwind null_pointer_is_valid optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+crc32,+cx8,+fsgsbase,+fxsr,+invpcid,+mmx,+popcnt,+rtm,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+ssse3,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 2}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"uwtable", i32 2}
!3 = !{i32 1, !"MaxTLSAlign", i32 65536}
!4 = !{!"clang version 777.1.7newworld (C:/workspace2/llvm-msvc/clang 6260b520c0a9347bf2e3caf538379d4c6cc86228)"}
