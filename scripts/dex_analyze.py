#!/usr/bin/env python3
"""最小化 DEX 解析器：提取类列表 + Android 类的 <clinit> 字节码引用的类型。"""
import struct, sys

def read_uleb128(data, off):
    result = 0; shift = 0
    while True:
        b = data[off]; off += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return result, off

def main(path):
    with open(path, 'rb') as f:
        data = f.read()

    string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
    string_ids_off  = struct.unpack_from('<I', data, 0x3c)[0]
    type_ids_size   = struct.unpack_from('<I', data, 0x40)[0]
    type_ids_off    = struct.unpack_from('<I', data, 0x44)[0]
    method_ids_size = struct.unpack_from('<I', data, 0x58)[0]
    method_ids_off  = struct.unpack_from('<I', data, 0x5c)[0]
    class_defs_size = struct.unpack_from('<I', data, 0x60)[0]
    class_defs_off  = struct.unpack_from('<I', data, 0x64)[0]

    print(f"DEX: {path}")
    print(f"  strings={string_ids_size} types={type_ids_size} methods={method_ids_size} classes={class_defs_size}")

    strings = []
    for i in range(string_ids_size):
        off = struct.unpack_from('<I', data, string_ids_off + i*4)[0]
        _, val_off = read_uleb128(data, off)
        end = data.index(0, val_off)
        strings.append(data[val_off:end].decode('utf-8', errors='replace'))

    types = []
    for i in range(type_ids_size):
        idx = struct.unpack_from('<I', data, type_ids_off + i*4)[0]
        types.append(strings[idx])

    method_names = {}
    for i in range(method_ids_size):
        base = method_ids_off + i * 8
        class_idx_m = struct.unpack_from('<H', data, base)[0]
        name_idx = struct.unpack_from('<I', data, base + 4)[0]
        method_names[i] = (types[class_idx_m], strings[name_idx])

    print(f"\n=== {class_defs_size} classes ===")
    for i in range(class_defs_size):
        base = class_defs_off + i * 32
        class_idx = struct.unpack_from('<I', data, base)[0]
        superclass_idx = struct.unpack_from('<I', data, base + 8)[0]
        class_data_off = struct.unpack_from('<I', data, base + 24)[0]
        class_name = types[class_idx]
        super_name = types[superclass_idx] if superclass_idx != 0xFFFFFFFF else "(none)"
        print(f"  [{i}] {class_name}  super={super_name}  data_off=0x{class_data_off:x}")

        if class_data_off == 0:
            continue
        off = class_data_off
        sf_size, off = read_uleb128(data, off)
        if_size, off = read_uleb128(data, off)
        dm_size, off = read_uleb128(data, off)
        vm_size, off = read_uleb128(data, off)

        for _ in range(sf_size):
            _, off = read_uleb128(data, off)
            _, off = read_uleb128(data, off)
        for _ in range(if_size):
            _, off = read_uleb128(data, off)
            _, off = read_uleb128(data, off)

        prev_method_idx = 0
        for _ in range(dm_size):
            diff, off = read_uleb128(data, off)
            cur_method_idx = prev_method_idx + diff
            prev_method_idx = cur_method_idx
            _, off = read_uleb128(data, off)  # access_flags
            code_off, off = read_uleb128(data, off)

            m_class, m_name = method_names.get(cur_method_idx, ("?", "?"))
            if m_name != "<clinit>":
                continue

            print(f"    >> <clinit>  code_off=0x{code_off:x}")
            if code_off == 0:
                print("       (no code)")
                continue

            insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
            insns_off = code_off + 16
            insn_data = data[insns_off:insns_off + insns_size * 2]

            type_refs = set()
            j = 0
            while j < len(insn_data) - 1:
                opcode = insn_data[j]
                # 21c 格式：AA|op BBBB (type_idx)
                if opcode in (0x1c, 0x1f, 0x22, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69):
                    if j + 3 < len(insn_data):
                        type_idx = struct.unpack_from('<H', insn_data, j + 2)[0]
                        if type_idx < len(types):
                            type_refs.add(types[type_idx])
                    j += 4
                # 35c 格式 invoke-*: 0x6e-0x78
                elif 0x6e <= opcode <= 0x78:
                    if j + 5 < len(insn_data):
                        mid = struct.unpack_from('<H', insn_data, j + 2)[0]
                        if mid in method_names:
                            mc, mn = method_names[mid]
                            type_refs.add(f"invoke→{mc}.{mn}")
                    j += 6
                else:
                    j += 2

            bc = sorted([t for t in type_refs if 'bouncycastle' in t.lower() or '$BCHolder' in t or 'Holder' in t])
            print(f"       BC/Holder refs: {bc if bc else 'NONE ✓'}")
            print(f"       all refs ({len(type_refs)}): {sorted(type_refs)[:25]}")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '/workspace/release/frameworkpatch.dex')
