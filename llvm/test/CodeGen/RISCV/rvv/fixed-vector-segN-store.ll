; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: sed 's/iXLen/i32/g' %s | llc -mtriple=riscv32 -mattr=+v -verify-machineinstrs | FileCheck %s -check-prefixes=CHECK,RV32
; RUN: sed 's/iXLen/i64/g' %s |llc -mtriple=riscv64 -mattr=+v -verify-machineinstrs | FileCheck %s -check-prefixes=CHECK,RV64

declare void @llvm.riscv.seg2.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor2(<8 x i8> %v0, <8 x i8> %v1, ptr %ptr) {
; CHECK-LABEL: store_factor2:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg2e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg2.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg3.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor3(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, ptr %ptr) {
; CHECK-LABEL: store_factor3:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg3e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg3.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg4.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor4(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, ptr %ptr) {
; CHECK-LABEL: store_factor4:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg4e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg4.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg5.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor5(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, ptr %ptr) {
; CHECK-LABEL: store_factor5:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg5e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg5.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg6.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor6(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, ptr %ptr) {
; CHECK-LABEL: store_factor6:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg6e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg6.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg7.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8x i8>, ptr, iXLen)
define void @store_factor7(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, <8 x i8> %v6, ptr %ptr) {
; CHECK-LABEL: store_factor7:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg7e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg7.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, <8 x i8> %v6, ptr %ptr, iXLen 8)
    ret void
}

declare void @llvm.riscv.seg8.store.v8i8.p0.iXLen(<8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, <8 x i8>, ptr, iXLen)
define void @store_factor8(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, <8 x i8> %v6, <8 x i8> %v7, ptr %ptr) {
; CHECK-LABEL: store_factor8:
; CHECK:       # %bb.0:
; CHECK-NEXT:    vsetivli zero, 8, e8, mf2, ta, ma
; CHECK-NEXT:    vsseg8e8.v v8, (a0)
; CHECK-NEXT:    ret
    call void @llvm.riscv.seg8.store.v8i8.p0.iXLen(<8 x i8> %v0, <8 x i8> %v1, <8 x i8> %v2, <8 x i8> %v3, <8 x i8> %v4, <8 x i8> %v5, <8 x i8> %v6, <8 x i8> %v7, ptr %ptr, iXLen 8)
    ret void
}
;; NOTE: These prefixes are unused and the list is autogenerated. Do not add tests below this line:
; RV32: {{.*}}
; RV64: {{.*}}
