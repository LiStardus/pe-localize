# PE 资源格式与本地化技术笔记

本文记录 Windows PE 文件里界面文字的存储格式，以及"原地等长替换"做本地化的技术要点。

## 1. 资源段 (.rsrc) 的位置

PE 文件头（`e_lfanew` 指向 NT 头）后是节表（section table）。找到名为 `.rsrc` 的节，记录两个值：

- `VirtualAddress` (VA)：资源段在内存中的 RVA。
- `PointerToRawData`：资源段在文件中的字节偏移。

资源树里的每个数据项（image resource data entry）存的是 **RVA**，转成文件偏移要：

```
file_offset = PointerToRawData + (rva - VirtualAddress)
```

这是第一个常见的坑：**偏移必须换算，不能直接用 RVA 当文件偏移**。

## 2. 资源目录树

资源是三层目录结构：**类型 → 名称/ID → 语言**。每层是 `IMAGE_RESOURCE_DIRECTORY` + 若干 `IMAGE_RESOURCE_DIRECTORY_ENTRY`。

遍历到第三层（语言）后，指向 `IMAGE_RESOURCE_DATA_ENTRY`，里面是 `{RVA, Size}`。

本工具关注的类型（type id）：

| type id | 资源 | 说明 |
|---|---|---|
| 4 | `RT_MENU` | 菜单 |
| 5 | `RT_DIALOG` | 对话框 |
| 6 | `RT_STRING` | 字符串表 |

> 注意：很多 exe 有多语言资源副本。本地化时通常选主语言（如 `lang=0x0409` 美式英语）那几条。本工具遍历所有语言的资源。

## 3. RT_STRING（字符串表）

- 按"块"组织，每块 16 条字符串，块号 = `(string_id >> 4) + 1`。
- 块内每条：`WORD 长度` + `UTF-16LE 字符串`（**无终止符**，长度就是字符数）。
- 空串长度为 0。

因为紧密排列、无终止符，**不能零填充**，必须保持每条的字节数不变。等长替换刚好满足：译文字符数 ≤ 原字符数，短了补空格（`0x0020`）。

## 4. RT_MENU

`MENUHEADER`（`wVersion`, `cbHeaderSize`）后是菜单项序列：

- 每项先一个 `WORD flags`（`MF_POPUP=0x10` 表示有子菜单）。
- 接一个 `ORDINAL 或 字符串`（`0xFFFF` 开头是序数，否则是 null 结尾的 UTF-16）。
- 非弹出项后面还有一个 `WORD wMenuID`。
- 子菜单项紧随其后嵌套排列。

## 5. RT_DIALOG（DIALOGEX）

对话框模板（`DIALOGEX`，`wVersion=1, wSignature=0xFFFF`）布局：

```
helpID(4) exStyle(4) style(4) cdit(2) x(2) y(2) w(2) h(2)   ← 头部共 26 字节
menu (ORDINAL 或 字符串)
class (ORDINAL 或 字符串)
caption (字符串)          ← 对话框标题，可翻译
[若 style & DS_SETFONT(0x40)]:
    pointsize(2) weight(2) italic(1) charset(1)
    typeface (字符串)     ← 字体名，不翻译
[cdit 个控件]             ← 每个 DWORD(4字节) 对齐
```

每个控件（`DLGITEMTEMPLATEEX`）：

```
helpID(4) exStyle(4) style(4) x(2) y(2) w(2) h(2) id(2)   ← 共 22 字节
class (ORDINAL 或 字符串)
title (ORDINAL 或 字符串)  ← 控件文字，可翻译
extra_size(2) + extra_data
```

### ⚠️ 关键坑：4 字节对齐

控件项是 **DWORD 对齐**的（每个控件起始偏移是 4 的倍数）。如果为了加长标题而整体移位，**位移量必须是 4 的倍数**，否则控件解析会错位、对话框打不开或崩溃。

要给标题扩容，正确做法是：从别处（例如某些文字的空格填充）腾出字节，保证总大小和后续偏移对齐不变。

## 6. 原地等长写回

核心原则：**只改文字的字节，不改长度、不改结构**。

1. 根据 extract 记录的绝对偏移，定位文字的字节区间。
2. 把译文编码成 UTF-16LE。
3. 译文比原文短：补 `0x0020`（空格）到原长度。
4. 译文比原文长：**跳过**（宁可不翻，也不能写坏）。
5. 文件大小保持不变，资源树所有 RVA/大小不动。

这样做的好处：程序必然能启动（结构没动），且可逆（有原文件备份即可还原）。

## 7. 其它注意事项

- **ASCII/ANSI 字符串**（`.rdata` 段里的错误提示等）不是 UTF-16，而是本地代码页（中文 Windows 是 GBK）。改这些要按 GBK 编码，且受原始字节长度限制。
- **图片资源**（PNG/图标）里的字节不是文字，按字符扫描会大量误判，要按资源类型过滤。
- **格式符和助记符**必须保留，否则程序行为异常。
- 交付前务必：① 自测启动 ② 逐个界面截图核对 ③ 保留原文件备份。
