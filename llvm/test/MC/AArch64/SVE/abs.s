// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sve < %s \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST
// RUN: llvm-mc -triple=aarch64 -show-encoding -mattr=+sme < %s \
// RUN:        | FileCheck %s --check-prefixes=CHECK-ENCODING,CHECK-INST
// RUN: not llvm-mc -triple=aarch64 -show-encoding < %s 2>&1 \
// RUN:        | FileCheck %s --check-prefix=CHECK-ERROR
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sve < %s \
// RUN:        | llvm-objdump -d --mattr=+sve - | FileCheck %s --check-prefix=CHECK-INST
// RUN: llvm-mc -triple=aarch64 -filetype=obj -mattr=+sve < %s \
// RUN:   | llvm-objdump -d --mattr=-sve - | FileCheck %s --check-prefix=CHECK-UNKNOWN

abs     z0.b, p0/m, z0.b
// CHECK-INST: abs     z0.b, p0/m, z0.b
// CHECK-ENCODING: [0x00,0xa0,0x16,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0416a000 <unknown>

abs     z0.h, p0/m, z0.h
// CHECK-INST: abs     z0.h, p0/m, z0.h
// CHECK-ENCODING: [0x00,0xa0,0x56,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0456a000 <unknown>

abs     z0.s, p0/m, z0.s
// CHECK-INST: abs     z0.s, p0/m, z0.s
// CHECK-ENCODING: [0x00,0xa0,0x96,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0496a000 <unknown>

abs     z0.d, p0/m, z0.d
// CHECK-INST: abs     z0.d, p0/m, z0.d
// CHECK-ENCODING: [0x00,0xa0,0xd6,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d6a000 <unknown>

abs     z31.b, p7/m, z31.b
// CHECK-INST: abs     z31.b, p7/m, z31.b
// CHECK-ENCODING: [0xff,0xbf,0x16,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0416bfff <unknown>

abs     z31.h, p7/m, z31.h
// CHECK-INST: abs     z31.h, p7/m, z31.h
// CHECK-ENCODING: [0xff,0xbf,0x56,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0456bfff <unknown>

abs     z31.s, p7/m, z31.s
// CHECK-INST: abs     z31.s, p7/m, z31.s
// CHECK-ENCODING: [0xff,0xbf,0x96,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0496bfff <unknown>

abs     z31.d, p7/m, z31.d
// CHECK-INST: abs     z31.d, p7/m, z31.d
// CHECK-ENCODING: [0xff,0xbf,0xd6,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d6bfff <unknown>


// --------------------------------------------------------------------------//
// Test compatibility with MOVPRFX instruction.

movprfx z4.d, p7/z, z6.d
// CHECK-INST: movprfx	z4.d, p7/z, z6.d
// CHECK-ENCODING: [0xc4,0x3c,0xd0,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d03cc4 <unknown>

abs     z4.d, p7/m, z31.d
// CHECK-INST: abs	z4.d, p7/m, z31.d
// CHECK-ENCODING: [0xe4,0xbf,0xd6,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d6bfe4 <unknown>

movprfx z4, z6
// CHECK-INST: movprfx	z4, z6
// CHECK-ENCODING: [0xc4,0xbc,0x20,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0420bcc4 <unknown>

abs     z4.d, p7/m, z31.d
// CHECK-INST: abs	z4.d, p7/m, z31.d
// CHECK-ENCODING: [0xe4,0xbf,0xd6,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d6bfe4 <unknown>
