#!/usr/bin/env python3
"""
pe_localize — PE 资源字符串本地化工具（提取 + 原地写回）。

原理：直接解析 PE (.rsrc) 资源树，定位 RT_STRING / RT_MENU / RT_DIALOG
里的文字字节，然后在原地做等长替换（短了用空格/零填充），绝不重编译资源，
因此不会破坏资源树结构，程序可正常启动。

这是通用工具，可用于任何 PE 可执行文件的界面文字本地化。
用法：
  python pe_localize.py extract  app.exe -o strings.json
  python pe_localize.py patch    app.exe strings.json -o app_localized.exe

strings.json 是 {"原文": "译文"} 映射；patch 时译文超过原长的会跳过（安全）。
"""
import struct, json, sys, argparse


def _u16(b, o): return struct.unpack_from('<H', b, o)[0]
def _u32(b, o): return struct.unpack_from('<I', b, o)[0]


class PE:
    def __init__(self, path):
        self.data = bytearray(open(path, 'rb').read())
        d = self.data
        e = _u32(d, 0x3c)
        nsec = _u16(d, e + 6)
        so = _u16(d, e + 20)
        st = e + 24 + so
        self.raw = self.va = None
        for i in range(nsec):
            o = st + i * 40
            if d[o:o+8].rstrip(b'\0') == b'.rsrc':
                self.va = _u32(d, o + 12)
                self.raw = _u32(d, o + 20)
        if self.raw is None:
            raise ValueError('no .rsrc section')
        self.rs = d[self.raw:]
        self.resources = []          # (type, id, lang, rva, size)
        self._walk(0, 0, None, None, None)

    def _walk(self, off, level, tid, rid, lang):
        nn, ni = _u16(self.rs, off + 12), _u16(self.rs, off + 14)
        for i in range(nn + ni):
            e0 = off + 16 + i * 8
            nf, v = _u32(self.rs, e0), _u32(self.rs, e0 + 4)
            if level == 0:   nt, nr, nl = nf, rid, lang
            elif level == 1: nt, nr, nl = tid, nf, lang
            else:            nt, nr, nl = tid, rid, nf
            if v & 0x80000000:
                self._walk(v & 0x7fffffff, level + 1, nt, nr, nl)
            else:
                de = v
                self.resources.append((nt, nr, nl, _u32(self.rs, de), _u32(self.rs, de + 4)))

    def blob(self, rva, size):
        fo = self.raw + (rva - self.va)
        return fo, self.data[fo:fo + size]


def _read_ord_or_str(buf, o):
    """读一个 dialog/menu 里的 ORDINAL 或字符串（带边界保护）。"""
    if o + 2 > len(buf):
        raise struct.error('oob')
    w = _u16(buf, o)
    if w == 0xFFFF:
        return ('ORD', _u16(buf, o + 2) if o + 4 <= len(buf) else 0), o + 4
    s = ''
    while True:
        if o + 2 > len(buf):
            raise struct.error('oob')
        w = _u16(buf, o); o += 2
        if w == 0: break
        s += chr(w)
    return ('STR', s), o


def extract_strings(pe):
    """提取 RT_STRING 文字：返回 [{off, units, text, ...}]。off 是文件绝对偏移。"""
    out = []
    for t, rid, lang, rva, size in pe.resources:
        if t != 6:  # RT_STRING
            continue
        fo, blob = pe.blob(rva, size)
        p = 0
        idx = 0
        while p + 2 <= len(blob):
            ln = _u16(blob, p)
            txt = blob[p + 2:p + 2 + ln * 2].decode('utf-16-le', 'ignore')
            if txt:
                out.append({'kind': 'string', 'resid': rid, 'idx': idx,
                            'off': fo + p + 2, 'units': ln, 'text': txt})
            p += 2 + ln * 2
            idx += 1
    return out


def extract_dialogs(pe):
    """提取 RT_DIALOG 标题/控件文字。"""
    out = []
    for t, rid, lang, rva, size in pe.resources:
        if t != 5:  # RT_DIALOG
            continue
        fo, blob = pe.blob(rva, size)
        is_ex = (_u16(blob, 0) == 1 and _u16(blob, 2) == 0xFFFF)
        if is_ex:
            style = _u32(blob, 12); cdit = _u16(blob, 16); o = 26
        else:
            style = _u32(blob, 0); cdit = _u16(blob, 8); o = 18
        # menu / class / caption
        _, o = _read_ord_or_str(blob, o)
        _, o = _read_ord_or_str(blob, o)
        cap_off = o
        k, o = _read_ord_or_str(blob, o)
        if k[0] == 'STR' and k[1].strip():
            out.append({'kind': 'caption', 'resid': rid, 'off': fo + cap_off,
                        'units': len(k[1]), 'text': k[1]})
        # font
        if style & 0x40:
            if is_ex: o += 6
            else:     o += 2
            _, o = _read_ord_or_str(blob, o)
        # 控件
        for _ in range(cdit):
            o = (o + 3) & ~3
            if o + 22 > len(blob):
                break
            o += 22
            try:
                _, o = _read_ord_or_str(blob, o)          # class
                t_off = o
                k, o = _read_ord_or_str(blob, o)          # title
            except struct.error:
                break
            if k[0] == 'STR' and k[1].strip():
                out.append({'kind': 'ctrl', 'resid': rid, 'off': fo + t_off,
                            'units': len(k[1]), 'text': k[1]})
            if o + 2 > len(blob):
                break
            o += 2 + _u16(blob, o)                    # extra
    return out


def extract_menus(pe):
    """提取 RT_MENU 文字。"""
    out = []
    for t, rid, lang, rva, size in pe.resources:
        if t != 4:  # RT_MENU
            continue
        fo, blob = pe.blob(rva, size)
        o = 2  # 跳过 MENUHEADER(wVersion, cbHeaderSize)
        while o + 2 <= len(blob):
            flags = _u16(blob, o); o += 2
            if o + 2 > len(blob):
                break
            # 弹出项(MF_POPUP)后接字符串+子菜单；普通项后接字符串+wMenuID
            t_off = o
            try:
                k, o = _read_ord_or_str(blob, o)
            except struct.error:
                break
            if k[0] == 'STR' and k[1].strip():
                out.append({'kind': 'menu', 'resid': rid, 'off': fo + t_off,
                            'units': len(k[1]), 'text': k[1]})
            if not (flags & 0x10):        # 非弹出项：后面还有 wMenuID
                o += 2
    return out


def cmd_extract(args):
    pe = PE(args.exe)
    items = extract_strings(pe) + extract_dialogs(pe) + extract_menus(pe)
    mapping = {}
    for it in items:
        mapping.setdefault(it['text'].strip(), it['text'])
    json.dump(mapping, open(args.out, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f"提取 {len(items)} 条文字 ({len(mapping)} 唯一) -> {args.out}")


def cmd_patch(args):
    trans = json.load(open(args.mapping, encoding='utf-8'))
    pe = PE(args.exe)
    items = extract_strings(pe) + extract_dialogs(pe) + extract_menus(pe)
    applied = skipped = 0
    for it in items:
        en = it['text']
        zh = trans.get(en) or trans.get(en.strip()) or trans.get(en.rstrip())
        if not zh or zh == en:
            continue
        if len(zh) > it['units']:
            skipped += 1; continue
        pad = it['units'] - len(zh)
        new = zh.encode('utf-16-le') + (b'\x20\x00' * pad)   # 短了空格填充
        pe.data[it['off']:it['off'] + it['units'] * 2] = new
        applied += 1
    open(args.out, 'wb').write(pe.data)
    print(f"应用 {applied} 处, 跳过 {skipped} 处(译文过长) -> {args.out}")


def main():
    ap = argparse.ArgumentParser(description='PE 资源字符串本地化工具')
    sub = ap.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('extract'); a.add_argument('exe'); a.add_argument('-o', '--out', required=True)
    a.set_defaults(func=cmd_extract)
    a = sub.add_parser('patch'); a.add_argument('exe'); a.add_argument('mapping')
    a.add_argument('-o', '--out', required=True); a.set_defaults(func=cmd_patch)
    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
