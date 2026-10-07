#!/usr/bin/env python3
r"""仅根据分发的 x86 PE 文件字节恢复《空城计》的 Flag。

在 Project_Mirage 工作目录中运行：
    python .\solutions\solve_empty_city.py
    python .\solutions\solve_empty_city.py .\dist\empty_city.exe

脚本不会读取 build/author/answer.json 或作者保存的明文 Flag。
它沿 PE TLS 回调指针找到内嵌 blob，从中读取 XTEA 密钥和密文，
再逆运算程序使用的 7 个 XTEA 分组。
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


DELTA = 0x9E3779B9
INITIAL_DECRYPT_SUM = 0xC6EF3720  # 32 * DELTA 对 2**32 取模后的初始解密 sum。
MASK32 = 0xFFFFFFFF
KEY_BLOB_OFFSET = 0x800
CIPHERTEXT_BLOB_OFFSET = 0x810
CIPHERTEXT_LENGTH = 56  # 共 7 个互相独立的 8 字节分组。


def u16(data: bytes, offset: int) -> int:
    """读取一个小端 WORD；越界时给出明确错误。"""
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(f"WORD 读取越过文件边界：文件偏移 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    """读取一个小端 DWORD；越界时给出明确错误。"""
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"DWORD 读取越过文件边界：文件偏移 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def parse_sections(data: bytes, pe_offset: int, optional_offset: int) -> tuple[int, list[dict[str, int]]]:
    """返回 ImageBase 和 PE 节表，用于把 RVA 映射到文件偏移。"""
    section_count = u16(data, pe_offset + 6)
    optional_size = u16(data, pe_offset + 20)
    section_table = optional_offset + optional_size
    sections: list[dict[str, int]] = []

    for index in range(section_count):
        off = section_table + index * 40
        if off + 40 > len(data):
            raise ValueError("节表超出文件末尾")
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_pointer = u32(data, off + 20)
        sections.append({
            "rva": virtual_address,
            "span": max(virtual_size, raw_size),
            "raw_size": raw_size,
            "raw": raw_pointer,
        })

    image_base = u32(data, optional_offset + 28)
    return image_base, sections


def rva_to_offset(rva: int, sections: list[dict[str, int]]) -> int:
    """根据 PE 节表把 RVA 转成文件偏移。"""
    for section in sections:
        start = section["rva"]
        delta = rva - start
        if 0 <= delta < section["span"]:
            if delta >= section["raw_size"]:
                raise ValueError(f"RVA 0x{rva:x} 位于只在内存中补零的数据区")
            return section["raw"] + delta
    raise ValueError(f"RVA 0x{rva:x} 不属于任何节")


def find_blob(data: bytes) -> tuple[int, int]:
    """沿 PE32 的 TLS 目录、回调数组和首个回调找到 blob 的文件偏移。"""
    if data[:2] != b"MZ":
        raise ValueError("缺少 DOS MZ 标记")

    pe_offset = u32(data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("缺少 PE 标记")
    if u16(data, pe_offset + 4) != 0x14C:
        raise ValueError("求解器要求 x86（IMAGE_FILE_MACHINE_I386）PE")

    optional_offset = pe_offset + 24
    if u16(data, optional_offset) != 0x10B:
        raise ValueError("求解器要求 PE32，不支持 PE32+")

    image_base, sections = parse_sections(data, pe_offset, optional_offset)

    # IMAGE_DIRECTORY_ENTRY_TLS 是数据目录索引 9。
    # PE32 的 Data Directory 数组从 Optional Header 起始偏移 96 字节处开始。
    tls_rva = u32(data, optional_offset + 96 + 9 * 8)
    if tls_rva == 0:
        raise ValueError("PE 中没有 TLS 目录")
    tls_offset = rva_to_offset(tls_rva, sections)

    # IMAGE_TLS_DIRECTORY32.AddressOfCallBacks 是结构中的第四个 DWORD（偏移 +0x0C）。
    callbacks_va = u32(data, tls_offset + 12)
    callbacks_rva = callbacks_va - image_base
    callbacks_offset = rva_to_offset(callbacks_rva, sections)

    # 以空指针结尾的回调数组第一项指向 blob 基址。
    blob_va = u32(data, callbacks_offset)
    blob_rva = blob_va - image_base
    blob_offset = rva_to_offset(blob_rva, sections)
    return image_base, blob_offset


def decrypt_xtea_block(block: bytes, key: list[int]) -> bytes:
    """解密一个 8 字节 XTEA 分组（32 个 cycle，小端 32 位字）。"""
    if len(block) != 8:
        raise ValueError("XTEA 分组长度必须恰好为 8 字节")

    v0, v1 = struct.unpack("<2I", block)
    total = INITIAL_DECRYPT_SUM

    for _ in range(32):
        # 先撤销 XTEA 的第二个 half-round。所有加减都按 uint32 回绕，
        # 与 x86 机器码里的 32 位寄存器运算一致。
        mix1 = ((((v0 << 4) & MASK32) ^ (v0 >> 5)) + v0) & MASK32
        key_index1 = (total >> 11) & 3
        v1 = (v1 - (mix1 ^ ((total + key[key_index1]) & MASK32))) & MASK32

        total = (total - DELTA) & MASK32

        # sum 已减去 delta，现在撤销第一个 half-round。
        mix0 = ((((v1 << 4) & MASK32) ^ (v1 >> 5)) + v1) & MASK32
        key_index0 = total & 3
        v0 = (v0 - (mix0 ^ ((total + key[key_index0]) & MASK32))) & MASK32

    return struct.pack("<2I", v0, v1)


def solve(exe_path: Path) -> str:
    data = exe_path.read_bytes()
    _image_base, blob_offset = find_blob(data)

    key = [
        u32(data, blob_offset + KEY_BLOB_OFFSET + index * 4)
        for index in range(4)
    ]
    cipher_start = blob_offset + CIPHERTEXT_BLOB_OFFSET
    ciphertext = data[cipher_start:cipher_start + CIPHERTEXT_LENGTH]
    if len(ciphertext) != CIPHERTEXT_LENGTH:
        raise ValueError("映射到的 blob 中没有完整的 56 字节密文")

    padded = b"".join(
        decrypt_xtea_block(ciphertext[offset:offset + 8], key)
        for offset in range(0, len(ciphertext), 8)
    )

    # PKCS#7 用 N 个数值为 N 的字节填充。本题 49 字节 Flag 补 7 个 0x07，
    # 解填充前的明文长度因此为 56 字节。
    padding = padded[-1]
    if not 1 <= padding <= 8 or padded[-padding:] != bytes([padding]) * padding:
        raise ValueError("PKCS#7 填充无效：密钥、偏移或算法可能不正确")
    flag_bytes = padded[:-padding]

    try:
        flag = flag_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("解出的明文不是 ASCII") from exc
    if not (flag.startswith("PKWCTF{") and flag.endswith("}")):
        raise ValueError("解出的明文不符合预期的 Flag 前后缀格式")
    return flag


def main() -> None:
    default_exe = Path(__file__).resolve().parents[1] / "dist" / "empty_city.exe"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", type=Path, default=default_exe,
                        help="题目 PE 路径（默认使用 dist/empty_city.exe）")
    args = parser.parse_args()
    print(solve(args.exe))


if __name__ == "__main__":
    main()
