// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sve2 < %s \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST
// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sme < %s \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST
// RUN: not llvm-mc -triple=aarch64 -show-encoding < %s 2>&1 \
// RUN:        | FileCheck %s --check-prefix=CHECK-ERROR
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sve2 < %s \
// RUN:        | llvm-objdump --no-print-imm-hex -d --mattr=+sve2 - | FileCheck %s --check-prefix=CHECK-INST
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sve2 < %s \
// RUN:   | llvm-objdump --no-print-imm-hex -d --mattr=-sve2 - | FileCheck %s --check-prefix=CHECK-UNKNOWN

sqshrnb     z0.b, z0.h, #1
// CHECK-INST: sqshrnb	z0.b, z0.h, #1
// CHECK-ENCODING: [0x00,0x20,0x2f,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 452f2000 <unknown>

sqshrnb     z31.b, z31.h, #8
// CHECK-INST: sqshrnb	z31.b, z31.h, #8
// CHECK-ENCODING: [0xff,0x23,0x28,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 452823ff <unknown>

sqshrnb     z0.h, z0.s, #1
// CHECK-INST: sqshrnb	z0.h, z0.s, #1
// CHECK-ENCODING: [0x00,0x20,0x3f,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 453f2000 <unknown>

sqshrnb     z31.h, z31.s, #16
// CHECK-INST: sqshrnb	z31.h, z31.s, #16
// CHECK-ENCODING: [0xff,0x23,0x30,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 453023ff <unknown>

sqshrnb     z0.s, z0.d, #1
// CHECK-INST: sqshrnb	z0.s, z0.d, #1
// CHECK-ENCODING: [0x00,0x20,0x7f,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 457f2000 <unknown>

sqshrnb     z31.s, z31.d, #32
// CHECK-INST: sqshrnb	z31.s, z31.d, #32
// CHECK-ENCODING: [0xff,0x23,0x60,0x45]
// CHECK-ERROR: instruction requires: sve2 or sme
// CHECK-UNKNOWN: 456023ff <unknown>
