import assert from "node:assert/strict";

/** Source-owned RV32/RV64 I instructions; no compiler or target execution needed.
 * File offset 0x1000 is entry; leaf is entry+0x20, global word is entry+0x30.
 * A zero-filled header exercises a real base/entry split without cropping bytes.
 */
export function riscvRawFixture(bits) {
  assert.ok(bits === 32 || bits === 64);
  const words = [
    0xff010113, // addi sp,sp,-16
    bits === 32 ? 0x00112623 : 0x00113423, // sw ra,12(sp) / sd ra,8(sp)
    0x018000ef, // jal ra,entry+0x20
    bits === 32 ? 0x00c12083 : 0x00813083, // lw ra,12(sp) / ld ra,8(sp)
    0x01010113, // addi sp,sp,16
    0x00008067, // ret
    0x00000013,
    0x00000013, // padding nops
    0x00000297, // leaf: auipc t0,0
    0x0102a503, // lw a0,16(t0) -- global
    0x00008067, // ret
    0x00000013, // padding nop
    7, // global
  ];
  const bytes = Buffer.alloc(0x1000 + words.length * 4);
  words.forEach((word, index) => bytes.writeUInt32LE(word, 0x1000 + index * 4));
  return bytes;
}
