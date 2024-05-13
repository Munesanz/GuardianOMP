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

fcvtzs  z0.h, p0/m, z0.h
// CHECK-INST: fcvtzs  z0.h, p0/m, z0.h
// CHECK-ENCODING: [0x00,0xa0,0x5a,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 655aa000 <unknown>

fcvtzs  z0.s, p0/m, z0.h
// CHECK-INST: fcvtzs  z0.s, p0/m, z0.h
// CHECK-ENCODING: [0x00,0xa0,0x5c,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 655ca000 <unknown>

fcvtzs  z0.s, p0/m, z0.s
// CHECK-INST: fcvtzs  z0.s, p0/m, z0.s
// CHECK-ENCODING: [0x00,0xa0,0x9c,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 659ca000 <unknown>

fcvtzs  z0.s, p0/m, z0.d
// CHECK-INST: fcvtzs  z0.s, p0/m, z0.d
// CHECK-ENCODING: [0x00,0xa0,0xd8,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 65d8a000 <unknown>

fcvtzs  z0.d, p0/m, z0.h
// CHECK-INST: fcvtzs  z0.d, p0/m, z0.h
// CHECK-ENCODING: [0x00,0xa0,0x5e,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 655ea000 <unknown>

fcvtzs  z0.d, p0/m, z0.s
// CHECK-INST: fcvtzs  z0.d, p0/m, z0.s
// CHECK-ENCODING: [0x00,0xa0,0xdc,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 65dca000 <unknown>

fcvtzs  z0.d, p0/m, z0.d
// CHECK-INST: fcvtzs  z0.d, p0/m, z0.d
// CHECK-ENCODING: [0x00,0xa0,0xde,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 65dea000 <unknown>


// --------------------------------------------------------------------------//
// Test compatibility with MOVPRFX instruction.

movprfx z5.d, p0/z, z7.d
// CHECK-INST: movprfx	z5.d, p0/z, z7.d
// CHECK-ENCODING: [0xe5,0x20,0xd0,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 04d020e5 <unknown>

fcvtzs  z5.d, p0/m, z0.d
// CHECK-INST: fcvtzs	z5.d, p0/m, z0.d
// CHECK-ENCODING: [0x05,0xa0,0xde,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 65dea005 <unknown>

movprfx z5, z7
// CHECK-INST: movprfx	z5, z7
// CHECK-ENCODING: [0xe5,0xbc,0x20,0x04]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 0420bce5 <unknown>

fcvtzs  z5.d, p0/m, z0.d
// CHECK-INST: fcvtzs	z5.d, p0/m, z0.d
// CHECK-ENCODING: [0x05,0xa0,0xde,0x65]
// CHECK-ERROR: instruction requires: sve or sme
// CHECK-UNKNOWN: 65dea005 <unknown>
