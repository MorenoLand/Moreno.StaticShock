"""Minimal PE32/PE32+ reader used by the lift scripts.

The guest image is addressed by virtual address. Image() exposes the raw file,
the section table, the image base, the entry point and the architecture;
read()/u32()/u16()/cstring() map a virtual address back to the file.
"""
import struct


class Image:
    def __init__(self, path):
        self.path = str(path)
        self.d = open(self.path, "rb").read()
        if self.d[:2] != b"MZ":
            raise ValueError("not an MZ image: %s" % self.path)
        pe = struct.unpack_from("<I", self.d, 0x3C)[0]
        if self.d[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE image: %s" % self.path)
        nsec = struct.unpack_from("<H", self.d, pe + 6)[0]
        opt_size = struct.unpack_from("<H", self.d, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", self.d, opt)[0]
        if magic == 0x10B:
            self.arch = "x86"
            self.is_64 = False
            self.base = struct.unpack_from("<I", self.d, opt + 28)[0]
        elif magic == 0x20B:
            self.arch = "x64"
            self.is_64 = True
            self.base = struct.unpack_from("<Q", self.d, opt + 24)[0]
        else:
            raise ValueError("unsupported PE optional header magic 0x%x" % magic)
        self.entry = self.base + struct.unpack_from("<I", self.d, opt + 16)[0]
        self.image_size = struct.unpack_from("<I", self.d, opt + 56)[0]
        self.opt = opt
        self.pe = pe
        self.secs = []
        sec_off = opt + opt_size
        for i in range(nsec):
            o = sec_off + i * 40
            name = self.d[o:o + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", self.d, o + 8)
            chars = struct.unpack_from("<I", self.d, o + 36)[0]
            self.secs.append((name, vsize, self.base + va, raw_size, raw_off))
            self._chars = getattr(self, "_chars", {})
            self._chars[name] = chars
        self._by_va = sorted(self.secs, key=lambda s: s[2])

    def off(self, v):
        for sec in self._by_va:
            name, vsize, va, raw_size, raw_off = sec[:5]
            if va <= v < va + max(vsize, raw_size):
                delta = v - va
                return raw_off + delta if delta < raw_size else None
        if self.base <= v < self.base + 0x1000:
            return v - self.base
        return None

    def read(self, v, n):
        o = self.off(v)
        if o is None:
            return b""
        return self.d[o:o + n]

    def u16(self, v):
        b = self.read(v, 2)
        return struct.unpack("<H", b)[0] if len(b) == 2 else None

    def u32(self, v):
        b = self.read(v, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else None

    def u64(self, v):
        b = self.read(v, 8)
        return struct.unpack("<Q", b)[0] if len(b) == 8 else None

    def cstring(self, v, limit=1024):
        out = bytearray()
        while len(out) < limit:
            b = self.read(v + len(out), 1)
            if not b or b == b"\0":
                break
            out += b
        return out.decode("latin-1")

    def section(self, name):
        for sec in self.secs:
            if sec[0] == name:
                return sec
        return None

    def imports(self):
        """Yield (module, iat_slot, name_or_ordinal) for the import directory."""
        dd = self.opt + (112 if self.is_64 else 96)
        rva = struct.unpack_from("<I", self.d, dd + 8)[0]
        if not rva:
            return []
        off = self.off(self.base + rva)
        if off is None:
            return []
        result = []
        step = 8 if self.is_64 else 4
        ordinal_bit = 1 << 63 if self.is_64 else 1 << 31
        value_mask = ordinal_bit - 1
        while True:
            desc = self.d[off:off + 20]
            if len(desc) < 20 or desc == b"\0" * 20:
                break
            ilt, _, _, name_rva, iat = struct.unpack("<IIIII", desc)
            module = self.cstring(self.base + name_rva)
            thunk = ilt or iat
            index = 0
            while True:
                slot_va = self.base + thunk + index * step
                value = self.u64(slot_va) if self.is_64 else self.u32(slot_va)
                if not value:
                    break
                if value & ordinal_bit:
                    result.append((module, self.base + iat + index * step, "#%d" % (value & 0xffff)))
                else:
                    result.append((module, self.base + iat + index * step,
                                   self.cstring(self.base + (value & value_mask) + 2)))
                index += 1
            off += 20
        return result
