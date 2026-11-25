#!/usr/bin/env python3
"""MCP server: droidasc (ASC Android decompiler) 的 agent 接口。

每个工具都是对 `droidasc` CLI 的一次调用（该 CLI 由 /opt/droidasc/venv 提供），
返回文本结果。大输出会被截断并带上"如何取全文"的提示：要么用 offset/limit 翻页，
要么传 output_path 让 CLI 把全文写进文件，工具只回预览。
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcp.server.mcpserver import MCPServer

DROIDASC = os.environ.get("DROIDASC_BIN") or shutil.which("droidasc") or "/usr/local/bin/droidasc"
DEFAULT_TIMEOUT = float(os.environ.get("DROIDASC_TIMEOUT", "300"))
MAX_CHARS = 60_000

mcp = MCPServer(
    name="droidasc",
    title="Droid ASC (Android decompiler)",
    instructions=(
        "droidasc 是快速的 Android/APK 反编译工具，不做 native 层。"
        "典型流程：apk_info 了解包 → apk_manifest 看清单/权限 → "
        "apk_list_classes 找类名 → apk_decompile_class 反编译成 Java / "
        "apk_disassemble_class 看 smali / apk_find_refs 跨 dex 找字符串、方法、类引用 / "
        "apk_strings 搜字符串池（硬编码 URL、密钥）/ apk_smali_grep 按 smali 指令模式跨类搜索（反射、加解密入口）。"
        "输出被截断时用 offset/limit 翻页，或给 output_path 写全文再读文件。"
    ),
    version="0.2.0",
)


class ToolError(Exception):
    """可预期的失败：路径不存在、CLI 报错等。"""


def _safe(fn):
    """工具体里抛的异常转成文本返回，模型才看得到原因（否则只剩 "Error executing tool"）。"""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:  # noqa: BLE001 - 兜底，仍要让模型看见
            return f"ERROR: {type(exc).__name__}: {exc}"

    return wrapper


# ---------------------------------------------------------------- 基础设施


def _apk(path: str) -> Path:
    if not path:
        raise ToolError("apk 参数为空")
    p = Path(os.path.expanduser(str(path))).resolve()
    if not p.is_file():
        raise ToolError(f"APK 不存在：{p}")
    if not os.access(p, os.R_OK):
        raise ToolError(f"APK 不可读：{p}")
    return p


def _run(args: list[str], timeout: float | None = None) -> str:
    """跑一次 droidasc，成功返回 stdout，失败抛 ToolError(含 stderr 尾部)。"""
    cmd = [DROIDASC, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout or DEFAULT_TIMEOUT,
            cwd=tempfile.gettempdir(),
        )
    except FileNotFoundError as exc:  # droidasc 没装
        raise ToolError(f"找不到 droidasc 可执行文件（{DROIDASC}）：{exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"droidasc 超时（{timeout or DEFAULT_TIMEOUT:.0f}s）：{' '.join(args[:3])}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        tail = "\n".join(detail.splitlines()[-20:])
        raise ToolError(f"droidasc 退出码 {proc.returncode}\n{tail}")
    return proc.stdout


def _clip(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        max_chars = MAX_CHARS
    if len(text) <= max_chars:
        return text
    return (
        text[:max_chars]
        + f"\n\n…[已截断：总长 {len(text)} 字符，只回前 {max_chars} 字符。"
        "用 offset/limit 翻页，或传 output_path 取全文]"
    )


def _page(text: str, offset: int, limit: int) -> str:
    lines = text.splitlines()
    total = len(lines)
    offset = max(0, offset)
    limit = limit if limit > 0 else 200
    if offset >= total:
        return f"[没有更多了：共 {total} 行，offset={offset}]"
    chunk = lines[offset : offset + limit]
    head = f"[第 {offset + 1}-{offset + len(chunk)} 行 / 共 {total} 行]\n"
    tail = ""
    if offset + len(chunk) < total:
        tail = f"\n[还有 {total - offset - len(chunk)} 行，offset={offset + len(chunk)} 继续]"
    return head + "\n".join(chunk) + tail


def _emit(text: str, output_path: str, label: str) -> str:
    """有 output_path 就写文件回预览，否则回（可能截断的）全文。"""
    if output_path:
        dest = Path(os.path.expanduser(output_path)).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        preview = "\n".join(text.splitlines()[:40])
        return f"[{label} 已写入 {dest}（{len(text)} 字符 / {len(text.splitlines())} 行）]\n\n{preview}"
    return _clip(text, MAX_CHARS)


def _threads(threads: int) -> list[str]:
    return ["--threads", str(threads)] if threads and threads > 0 else []


# ------------------------------------------------- 字符串池解析（dex / arsc / raw）


def _uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(buf):
            raise IndexError("uleb128 越界")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _mutf8(raw: bytes) -> str:
    """MUTF-8：基本等同 UTF-8，只有 NUL 和代理对写法不同，非法字节降级成替换符。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def _dex_strings(buf: bytes) -> list[str]:
    """读 classes*.dex 的 string_ids 表（header 0x38/0x3C），不依赖任何第三方 dex 库。"""
    if len(buf) < 0x70 or not buf.startswith(b"dex\n"):
        return []
    try:
        count, ids_off = struct.unpack_from("<II", buf, 0x38)
    except struct.error:
        return []
    if count <= 0 or ids_off <= 0 or ids_off >= len(buf):
        return []
    out: list[str] = []
    for i in range(count):
        pos = ids_off + 4 * i
        if pos + 4 > len(buf):
            break
        (data_off,) = struct.unpack_from("<I", buf, pos)
        if data_off >= len(buf):
            continue
        try:
            _, start = _uleb128(buf, data_off)
        except IndexError:
            continue
        end = buf.find(b"\x00", start)
        if end < 0:
            end = len(buf)
        out.append(_mutf8(buf[start:end]))
    return out


def _u8len(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise IndexError("长度越界")
    first = buf[pos]
    pos += 1
    if first & 0x80:
        if pos >= len(buf):
            raise IndexError("长度越界")
        return ((first & 0x7F) << 8) | buf[pos], pos + 1
    return first, pos


def _u16len(buf: bytes, pos: int) -> tuple[int, int]:
    if pos + 2 > len(buf):
        raise IndexError("长度越界")
    (first,) = struct.unpack_from("<H", buf, pos)
    pos += 2
    if first & 0x8000:
        if pos + 2 > len(buf):
            raise IndexError("长度越界")
        (low,) = struct.unpack_from("<H", buf, pos)
        return ((first & 0x7FFF) << 16) | low, pos + 2
    return first, pos


def _arsc_pool(buf: bytes, pos: int, hsize: int, size: int) -> list[str]:
    """RES_STRING_POOL_TYPE(0x0001)：UTF-8 池是 (字符数,字节数) 双变长长度，UTF-16 池是单长度。"""
    if pos + hsize + 12 > len(buf):
        return []
    count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", buf, pos + 8)
    utf8 = bool(flags & 0x100)
    base = pos + strings_start
    end = min(len(buf), pos + size)
    out: list[str] = []
    for i in range(count):
        off_pos = pos + hsize + 4 * i
        if off_pos + 4 > end:
            break
        (offset,) = struct.unpack_from("<I", buf, off_pos)
        cursor = base + offset
        if cursor >= end:
            continue
        try:
            if utf8:
                _chars, cursor = _u8len(buf, cursor)
                nbytes, cursor = _u8len(buf, cursor)
                out.append(buf[cursor : cursor + nbytes].decode("utf-8", "replace"))
            else:
                nchars, cursor = _u16len(buf, cursor)
                out.append(buf[cursor : cursor + 2 * nchars].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            continue
    return out


def _arsc_strings(buf: bytes) -> list[str]:
    """ResTable(0x0002) 里逐个子块找字符串池；只取全局 default 池（即 resources.arsc 顶层）。"""
    if len(buf) < 12:
        return []
    ctype, hsize, total = struct.unpack_from("<HHI", buf, 0)
    if ctype != 0x0002 or hsize < 12:
        return []
    out: list[str] = []
    pos, end = hsize, min(len(buf), total)
    while pos + 8 <= end:
        ctype, chsize, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8:
            break
        if ctype == 0x0001:
            out.extend(_arsc_pool(buf, pos, chsize, csize))
        pos += csize
    return out


_RAW_ENTRY_RE = re.compile(r"^(?:assets/.+|res/raw/.+)$")
_RAW_TEXT_EXT = (
    ".json", ".js", ".txt", ".properties", ".cfg", ".ini", ".html", ".htm", ".xml", ".plist", ".yaml", ".yml",
)


def _raw_strings(path: Path, budget: int, min_len: int) -> list[str]:
    """解压 assets/、res/raw/ 与常见文本文件，抓里面的可打印串（JSON 配置、壳的 JS 等）。"""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(4, min_len))
    out: list[str] = []
    used = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.filename.startswith("META-INF/"):
                continue
            name = info.filename
            if not (_RAW_ENTRY_RE.match(name) or name.lower().endswith(_RAW_TEXT_EXT)):
                continue
            if info.file_size > budget - used:
                continue
            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
                continue
            used += len(data)
            out.extend(m.group(0).decode("ascii", "replace") for m in pattern.finditer(data))
            if used >= budget:
                break
    return out


def _searchable(text: str) -> bool:
    """丢掉含控制字符/替换符的串（dex 池里大量二进制垃圾）。"""
    return bool(text) and "\ufffd" not in text and all(ch >= " " or ch == "\t" for ch in text)


def _matcher(pattern: str, regex: bool, ignore_case: bool):
    if regex:
        try:
            compiled = re.compile(pattern, re.I if ignore_case else 0)
        except re.error as exc:
            raise ToolError(f"正则表达式无效：{exc}") from exc
        return compiled.search
    if ignore_case:
        needle = pattern.lower()
        return lambda text: needle in text.lower()
    return lambda text: pattern in text


# ---------------------------------------------------------------- 工具


@mcp.tool()
@_safe
def apk_info(apk: str) -> str:
    """APK 概况：包名、版本、SDK、大小、dex 数量与权限数量（不反编译，最快）。"""
    p = _apk(apk)
    manifest = _run(["getmanifest", str(p)])
    head = re.search(r"<manifest\b[^>]*>", manifest, re.S)
    attrs = dict(re.findall(r'([\w:]+)="([^"]*)"', head.group(0))) if head else {}
    sdk = re.search(r"<uses-sdk\b[^>]*>", manifest)
    if sdk:
        for key, val in re.findall(r'([\w:]+)="([^"]*)"', sdk.group(0)):
            attrs.setdefault(key, val)
    perms = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', manifest)
    try:
        with zipfile.ZipFile(p) as zf:
            dex = sorted(n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n))
            libs = sorted({n.split("/")[1] for n in zf.namelist() if n.startswith("lib/") and n.count("/") > 1})
    except zipfile.BadZipFile as exc:
        raise ToolError(f"不是合法 APK/ZIP：{p}（{exc}）") from exc
    lines = [
        f"path: {p}",
        f"size: {p.stat().st_size / 1048576:.1f} MiB",
        f"package: {attrs.get('package', '?')}",
        f"versionName: {attrs.get('android:versionName', '?')}  versionCode: {attrs.get('android:versionCode', '?')}",
        f"minSdk: {attrs.get('android:minSdkVersion', '?')}  targetSdk: {attrs.get('android:targetSdkVersion', '?')}"
        f"  compileSdk: {attrs.get('android:compileSdkVersion', '?')}",
        f"dex: {len(dex)} 个" + (f"（{', '.join(dex[:4])}{' …' if len(dex) > 4 else ''}）" if dex else ""),
        f"native ABI: {', '.join(libs) if libs else '无 lib/ 目录'}",
        f"permissions: {len(perms)} 个",
    ]
    return "\n".join(lines)


@mcp.tool()
@_safe
def apk_manifest(apk: str, output_path: str = "") -> str:
    """把 AndroidManifest.xml 解成可读 XML（完整清单，含组件与权限）。"""
    p = _apk(apk)
    return _emit(_run(["getmanifest", str(p)]), output_path, "manifest")


@mcp.tool()
@_safe
def apk_list_classes(apk: str, prefix: str = "", offset: int = 0, limit: int = 200) -> str:
    """列出 APK 里的 Dalvik 类描述符（Lcom/x/Y;），可按包/类前缀过滤；按行分页。"""
    p = _apk(apk)
    args = ["listclass", str(p)]
    if prefix:
        args += ["--prefix", prefix]
    return _page(_run(args), offset, limit)


@mcp.tool()
@_safe
def apk_decompile_class(
    apk: str,
    class_name: str,
    output_path: str = "",
    threads: int = 0,
    max_chars: int = 0,
) -> str:
    """反编译单个类成 Java。class_name 接受 Lcom/x/Y; 或 com.x.Y。"""
    p = _apk(apk)
    text = _run(["getclass", str(p), class_name, *_threads(threads)])
    if output_path:
        return _emit(text, output_path, "java")
    return _clip(text, max_chars or MAX_CHARS)


@mcp.tool()
@_safe
def apk_disassemble_class(
    apk: str,
    class_name: str,
    method: str = "",
    debug_info: bool = False,
    output_path: str = "",
    threads: int = 0,
    max_chars: int = 0,
) -> str:
    """把单个类反汇编成 smali；method 传完整签名（如 'onCreate(Landroid/os/Bundle;)V'）可只看一个方法。"""
    p = _apk(apk)
    args = ["disassemble", str(p), class_name, *_threads(threads)]
    if method:
        args += ["--method", method]
    if debug_info:
        args.append("--debuginfo")
    text = _run(args)
    if output_path:
        return _emit(text, output_path, "smali")
    return _clip(text, max_chars or MAX_CHARS)


@mcp.tool()
@_safe
def apk_find_refs(
    apk: str,
    query: str,
    kind: str = "string",
    class_name: str = "",
    fuzzy_class: bool = False,
    output_path: str = "",
    offset: int = 0,
    limit: int = 200,
) -> str:
    """跨所有 dex 找引用。kind=string|type|method|field|extends|impl。

    method 建议配 class_name（类名可用简单的 'MainActivity' 并设 fuzzy_class=true 做模糊匹配）；
    extends/impl 用来找继承某类、实现某接口的所有类（query 传父类/接口全名，如 android.app.Activity）。
    """
    p = _apk(apk)
    kind = (kind or "string").strip().lower()
    aliases = {"extends": "extends", "impl": "impl", "implement": "impl", "implements": "impl"}
    kind = aliases.get(kind, kind)
    if kind not in {"string", "type", "method", "field", "extends", "impl"}:
        raise ToolError(f"kind 只能是 string/type/method/field/extends/impl，收到 {kind!r}")
    args = ["findrefs", str(p), kind, query]
    if kind == "method" and class_name:
        args += ["--class", class_name]
        if fuzzy_class:
            args.append("--fuzzy-class")
    if output_path:
        dest = Path(os.path.expanduser(output_path)).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        args += ["-o", str(dest)]
        _run(args)
        text = dest.read_text(encoding="utf-8", errors="replace")
        return _page(text, offset, limit)
    return _page(_run(args), offset, limit)


@mcp.tool()
@_safe
def apk_strings(
    apk: str,
    pattern: str = "",
    regex: bool = False,
    ignore_case: bool = False,
    min_len: int = 4,
    sources: str = "dex,arsc",
    max_scan_mb: int = 64,
    offset: int = 0,
    limit: int = 200,
) -> str:
    """搜索 APK 里的字符串：硬编码 URL、API key/密钥、特征提示语。

    sources 逗号分隔：
      dex  —— 所有 classes*.dex 的字符串池（最全，覆盖代码里所有常量）
      arsc —— resources.arsc 的全局字符串池（XML 里写的文案/地址）
      raw  —— 解压 assets/、res/raw/ 与 json/js/txt 等文本文件后抓可打印串（壳的配置、H5 资源）
    pattern 为空表示不过滤（只要 min_len 以上）。regex=true 时按 Python 正则匹配。
    结果按出现顺序去重后分页。
    """
    p = _apk(apk)
    wanted = {item.strip().lower() for item in (sources or "dex,arsc").split(",") if item.strip()}
    unknown = wanted - {"dex", "arsc", "raw"}
    if unknown:
        raise ToolError(f"sources 只能是 dex/arsc/raw 的组合，收到：{', '.join(sorted(unknown))}")
    if not wanted:
        raise ToolError("sources 为空")
    min_len = max(1, min_len)
    budget = max(1, max_scan_mb) * 1048576
    match = _matcher(pattern, regex, ignore_case) if pattern else None

    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    scanned: dict[str, int] = {}
    dropped = 0

    def feed(label: str, texts: list[str]) -> None:
        nonlocal dropped
        scanned[label] = scanned.get(label, 0) + len(texts)
        for text in texts:
            if len(text) < min_len or not _searchable(text):
                continue
            if match is not None and not match(text):
                continue
            if text in seen:
                continue
            if len(found) >= 200_000:
                dropped += 1
                continue
            seen.add(text)
            found.append((label, text))

    try:
        with zipfile.ZipFile(p) as zf:
            names = zf.namelist()
            if "dex" in wanted:
                dex_names = sorted(
                    (n for n in names if re.fullmatch(r"classes\d*\.dex", n)),
                    key=lambda n: int(re.fullmatch(r"classes(\d*)\.dex", n).group(1) or 1),
                )
                for name in dex_names:
                    feed("dex", _dex_strings(zf.read(name)))
            if "arsc" in wanted and "resources.arsc" in names:
                feed("arsc", _arsc_strings(zf.read("resources.arsc")))
    except zipfile.BadZipFile as exc:
        raise ToolError(f"不是合法 APK/ZIP：{p}（{exc}）") from exc
    if "raw" in wanted:
        feed("raw", _raw_strings(p, budget, min_len))

    stats = "  ".join(f"{label}: {n} 条串" for label, n in scanned.items()) or "未扫描任何来源"
    head = [
        f"[扫到 {stats}]",
        f"[sources={','.join(sorted(wanted))}  pattern={pattern!r}  min_len={min_len}"
        f"{'  regex' if regex else ''}{'  ignore_case' if ignore_case else ''}]",
        f"[命中 {len(found)} 条]" + (f"（超过 20 万条上限，丢弃 {dropped} 条）" if dropped else ""),
    ]
    if not found:
        return "\n".join(head) + "\n（没有命中；放宽 pattern 或把 sources 加上 raw 试试）"
    body = [f"[{label}] {text}" for label, text in found]
    return "\n".join(head) + "\n" + _page("\n".join(body), offset, limit)


@mcp.tool()
@_safe
def apk_smali_grep(
    apk: str,
    pattern: str,
    class_prefix: str = "",
    class_names: str = "",
    max_classes: int = 200,
    jobs: int = 8,
    regex: bool = False,
    ignore_case: bool = False,
    timeout: float = 120,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """跨类 grep smali 指令：找反射入口、加解密调用、日志/网络特征。

    做法是对每个候选类跑一次 `droidasc disassemble` 再逐行匹配，所以有扫描上限：
      class_names —— 逗号分隔的类名（ Lcom/x/Y; 或 com.x.Y ），直接指定要扫的类
      class_prefix —— 否则按类名前缀过滤（如 Lcom/tencent/mobileqq/utils/），取前 max_classes 个
    max_classes 默认 200、上限 1000；jobs 是并发反汇编数（默认 8）。
    例：pattern='Ljava/lang/reflect/Method;->invoke' 找反射；pattern='Ljavax/crypto/Cipher;->' 找加解密。
    """
    p = _apk(apk)
    if not pattern:
        raise ToolError("pattern 不能为空")
    match = _matcher(pattern, regex, ignore_case)
    jobs = max(1, min(int(jobs or 8), 32))
    max_classes = max(1, min(int(max_classes or 200), 1000))

    if class_names.strip():
        targets = [item.strip() for item in class_names.split(",") if item.strip()]
        rest = targets[max_classes:]
        targets = targets[:max_classes]
        scope = f"指定 {len(targets)} 个类"
    else:
        args = ["listclass", str(p)]
        if class_prefix:
            args += ["--prefix", class_prefix]
        listing = [line.strip() for line in _run(args).splitlines() if line.strip()]
        rest = listing[max_classes:]
        targets = listing[:max_classes]
        where = f"前缀 {class_prefix}" if class_prefix else "全量"
        scope = f"{where}候选 {len(listing)} 个类 → 取前 {len(targets)} 个"
    if not targets:
        return f"[{scope}]（没有候选类；换个 class_prefix 或直接用 class_names）"

    def scan(name: str):
        try:
            return name, _run(["disassemble", str(p), name], timeout=timeout).splitlines()
        except ToolError:
            return name, None

    hits: list[tuple[str, int, str]] = []
    skipped: list[str] = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for name, lines in pool.map(scan, targets):
            if lines is None:
                skipped.append(name)
                continue
            for lineno, line in enumerate(lines, 1):
                if match(line):
                    hits.append((name, lineno, line.strip()))

    head = [
        f"[{scope}，jobs={jobs}]",
        f"[pattern={pattern!r}{'  regex' if regex else ''}{'  ignore_case' if ignore_case else ''}"
        f"  命中 {len(hits)} 行 / {len({name for name, _, _ in hits})} 个类]",
    ]
    if skipped:
        head.append(f"[{len(skipped)} 个类反汇编失败已跳过：{', '.join(skipped[:5])}{' …' if len(skipped) > 5 else ''}]")
    if rest:
        head.append(f"[还有 {len(rest)} 个类没扫（max_classes={max_classes}）；缩小 class_prefix 或提高上限]")
    if not hits:
        return "\n".join(head) + "\n（没有命中；确认模式大小写/是否带 L 描述符）"

    body: list[str] = []
    current = None
    for name, lineno, line in hits:
        if name != current:
            body.append(f"\n{name}")
            current = name
        body.append(f"  {lineno}: {line}")
    return "\n".join(head) + "\n" + _page("\n".join(body).strip("\n"), offset, limit)


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
