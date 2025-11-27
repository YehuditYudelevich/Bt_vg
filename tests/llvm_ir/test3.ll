; ModuleID = 'test3.c'
source_filename = "test3.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind uwtable
define dso_local void @process_network_data(i8* %0) #0 !dbg !20 {
  %2 = alloca i8*, align 8
  %3 = alloca [50 x i8], align 16
  store i8* %0, i8** %2, align 8
  call void @llvm.dbg.declare(metadata i8** %2, metadata !26, metadata !DIExpression()), !dbg !27
  call void @llvm.dbg.declare(metadata [50 x i8]* %3, metadata !28, metadata !DIExpression()), !dbg !32
  %4 = getelementptr inbounds [50 x i8], [50 x i8]* %3, i64 0, i64 0, !dbg !33
  %5 = load i8*, i8** %2, align 8, !dbg !34
  %6 = call i8* @strcpy(i8* %4, i8* %5) #4, !dbg !35
  ret void, !dbg !36
}

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind
declare dso_local i8* @strcpy(i8*, i8*) #2

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @main() #0 !dbg !37 {
  %1 = alloca i32, align 4
  %2 = alloca [200 x i8], align 16
  %3 = alloca i32, align 4
  store i32 0, i32* %1, align 4
  call void @llvm.dbg.declare(metadata [200 x i8]* %2, metadata !41, metadata !DIExpression()), !dbg !45
  call void @llvm.dbg.declare(metadata i32* %3, metadata !46, metadata !DIExpression()), !dbg !47
  %4 = call i32 @socket(i32 2, i32 1, i32 0) #4, !dbg !48
  store i32 %4, i32* %3, align 4, !dbg !47
  %5 = load i32, i32* %3, align 4, !dbg !49
  %6 = getelementptr inbounds [200 x i8], [200 x i8]* %2, i64 0, i64 0, !dbg !50
  %7 = call i64 @recv(i32 %5, i8* %6, i64 200, i32 0), !dbg !51
  %8 = getelementptr inbounds [200 x i8], [200 x i8]* %2, i64 0, i64 0, !dbg !52
  call void @process_network_data(i8* %8), !dbg !53
  ret i32 0, !dbg !54
}

; Function Attrs: nounwind
declare dso_local i32 @socket(i32, i32, i32) #2

declare dso_local i64 @recv(i32, i8*, i64, i32) #3

attributes #0 = { noinline nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable willreturn }
attributes #2 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!16, !17, !18}
!llvm.ident = !{!19}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "test3.c", directory: "/mnt/c/Users/Yehudit/Desktop/groq_test/vuln_dinder/tests")
!2 = !{!3}
!3 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "__socket_type", file: !4, line: 24, baseType: !5, size: 32, elements: !6)
!4 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/socket_type.h", directory: "")
!5 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!6 = !{!7, !8, !9, !10, !11, !12, !13, !14, !15}
!7 = !DIEnumerator(name: "SOCK_STREAM", value: 1, isUnsigned: true)
!8 = !DIEnumerator(name: "SOCK_DGRAM", value: 2, isUnsigned: true)
!9 = !DIEnumerator(name: "SOCK_RAW", value: 3, isUnsigned: true)
!10 = !DIEnumerator(name: "SOCK_RDM", value: 4, isUnsigned: true)
!11 = !DIEnumerator(name: "SOCK_SEQPACKET", value: 5, isUnsigned: true)
!12 = !DIEnumerator(name: "SOCK_DCCP", value: 6, isUnsigned: true)
!13 = !DIEnumerator(name: "SOCK_PACKET", value: 10, isUnsigned: true)
!14 = !DIEnumerator(name: "SOCK_CLOEXEC", value: 524288, isUnsigned: true)
!15 = !DIEnumerator(name: "SOCK_NONBLOCK", value: 2048, isUnsigned: true)
!16 = !{i32 7, !"Dwarf Version", i32 4}
!17 = !{i32 2, !"Debug Info Version", i32 3}
!18 = !{i32 1, !"wchar_size", i32 4}
!19 = !{!"clang version 10.0.0-4ubuntu1 "}
!20 = distinct !DISubprogram(name: "process_network_data", scope: !1, file: !1, line: 4, type: !21, scopeLine: 4, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !25)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !23}
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!25 = !{}
!26 = !DILocalVariable(name: "data", arg: 1, scope: !20, file: !1, line: 4, type: !23)
!27 = !DILocation(line: 4, column: 33, scope: !20)
!28 = !DILocalVariable(name: "buf", scope: !20, file: !1, line: 5, type: !29)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 400, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 50)
!32 = !DILocation(line: 5, column: 10, scope: !20)
!33 = !DILocation(line: 6, column: 12, scope: !20)
!34 = !DILocation(line: 6, column: 17, scope: !20)
!35 = !DILocation(line: 6, column: 5, scope: !20)
!36 = !DILocation(line: 7, column: 1, scope: !20)
!37 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 9, type: !38, scopeLine: 9, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !25)
!38 = !DISubroutineType(types: !39)
!39 = !{!40}
!40 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!41 = !DILocalVariable(name: "network_buffer", scope: !37, file: !1, line: 10, type: !42)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 1600, elements: !43)
!43 = !{!44}
!44 = !DISubrange(count: 200)
!45 = !DILocation(line: 10, column: 10, scope: !37)
!46 = !DILocalVariable(name: "sock", scope: !37, file: !1, line: 11, type: !40)
!47 = !DILocation(line: 11, column: 9, scope: !37)
!48 = !DILocation(line: 11, column: 16, scope: !37)
!49 = !DILocation(line: 13, column: 10, scope: !37)
!50 = !DILocation(line: 13, column: 16, scope: !37)
!51 = !DILocation(line: 13, column: 5, scope: !37)
!52 = !DILocation(line: 14, column: 26, scope: !37)
!53 = !DILocation(line: 14, column: 5, scope: !37)
!54 = !DILocation(line: 15, column: 5, scope: !37)
