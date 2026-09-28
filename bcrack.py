# -*- coding: utf-8 -*-
"""
============================================================================
  文档密码破译器  v1.2    (docx/xlsx/pptx + doc/xls/ppt + PDF + ZIP)
============================================================================
  支持的加密体系：
      - Office 2007+ Agile 加密   : AES-128/192/256 + SHA1/256/384/512
      - Office Standard/CryptoAPI : AES-128 / RC4-40/128（Office 2002-2008）
      - Office 97-2003 XOR 混淆   : Word .doc legacy（常量表按 [MS-OFFCRYPTO]）
      - PDF : R2/R3/R4（RC4-40/128 + AES-128）与 R6（AES-256，PDF 2.0）
      - ZIP : ZipCrypto（传统 PKWARE）与 WinZip AES（PBKDF2-HMAC-SHA1）

  运行环境：
      - Python 3.8+（64 位；Windows / Linux / macOS 均可），纯标准库即可运行。
      - 可选依赖（装了自动用，没装会提示并可自动安装）：
            cryptography      -> AES 大文件解密导出提速 100 倍；PDF R6 提速
            msoffcrypto-tool  -> 找到密码后的第三方复核
            cupy-cuda12x/13x  -> GPU 加速（30/40/50 系及更早 NVIDIA 显卡，
                                 按驱动版本自动选择正确的包）
      - GPU 模式快约 60 倍。GPU 不可用时脚本会诊断原因（无显卡 / 驱动过旧 /
        缺依赖），经确认后自动 pip 安装并直接继续，无需重启脚本。

  v1.2.1：
      - 兼容 CuPy 14（NVRTC arch 参数从 'sm_120' 改为裸数字 '120'）
      - cupy DLL 被 Windows 应用程序控制策略拦截时给出明确指引，
        不再误报为"未安装"并无效重装

  v1.2.2：
      - 修复 GPU 6 位纯数字通道的致命 bug：CUDA 内核按 pwbuf 是否为空指针分支，
        而主机端 digits 模式传的是 1 字节 dummy（非 NULL），内核于是永远走缓冲分支、
        从 1 字节 buffer 按 idx*16 越界读 16 字节 —— 000000-999999 这一百万个密码
        一个都没被真正测试过，全空间扫完只会报"未找到"。改为显式 use_buf 开关。
      - 修复空密码 "" 被当成"未找到"（if not found -> if found is None）。
      - 修复 GBK 控制台/输出重定向时，汇总行的 ✔ ✘ 抛 UnicodeEncodeError 直接崩溃，
        导致跑完看不到结论。
      - 修复"整轮扫完但未命中"后进度文件残留，下次续扫会 0 任务秒退报未找到。
      - GPU 定长槽改按实际字节数打包，密码 >15 字节不再撑爆 16 字节槽导致后续全部错位。
      - 新增 selftest_gpu.py：用已知密码的合成参数 20 秒自检各条链路。

  常用命令：
      python bcrack.py                       # 交互式选择文件（可拖拽）
      python bcrack.py -f "x.docx"           # 直接指定文件
      python bcrack.py -f "a.pdf" -f "b.zip" # 多文件批处理
      python bcrack.py -f dir/               # 目录批处理（office+pdf）
      python bcrack.py --no-gpu               # 强制只用 CPU
      python bcrack.py -w 16                  # CPU 模式进程数
      python bcrack.py --start 300000 --end 700000
      python bcrack.py --charset digits --min-len 4 --max-len 8
      python bcrack.py --wordlist rockyou.txt
      python bcrack.py --resume                # 断点续扫（默认自动检测）
      python bcrack.py --info -f "x.docx"     # 只看加密参数，不破解
      python bcrack.py --check-deps            # 依赖体检

  断点续扫：中断 / GPU 出错回退 CPU 都会保存进度到 <文件>.bcrack.json，
  下次运行自动询问是否接着上次的进度继续，不重复已扫描的部分。

  性能参考（RTX 5060 Laptop 8GB + R9 8945HX 实测，10 万次 SHA512 迭代）：
      GPU  约 11700 密码/秒  -> 100 万约 90 秒
      CPU  约   171 密码/秒  -> 100 万约 97 分钟（32 进程）
      * ETA 使用运行时实测速度（滑动平均），不再依赖固定经验值。

  ⚠ 用途声明：本工具仅用于找回【你自己拥有】的文档密码（忘记密码的
    个人文件 rescue）。请勿用于未经授权访问他人文档。

  打包为免安装 EXE（可选）：
      pip install pyinstaller
      pyinstaller --onefile --name bcrack bcrack.py
      （多进程 spawn 在 -F 模式下已由 freeze_support 兼容；如需 GPU，
       需在目标机安装 cupy 或改为 --onedir 打包带上 cupy）
============================================================================
"""

import argparse
import base64
import glob
import hashlib
import hmac
import io
import multiprocessing as mp
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import zipfile
import zlib

VERSION = "1.2.2"
TOTAL_SPACE = 1000000          # 默认空间 000000-999999
DEFAULT_CHUNK = 25             # 每个任务分片包含的密码个数
PROGRESS_REFRESH = 0.4         # 进度刷新间隔(秒)
MAX_PW_LEN = 15                # 单条密码最大字节长度（GPU 缓冲区步长 16）


def pack_pw_slot(pw):
    """把一个密码打包进 16 字节定长槽。返回 (utf-8 bytes, plen)。
    plen 必须等于实际写入的字节数：内核按 plen 逐个当成 UTF-16 码元用，
    用字符长度会在 >15 字节时越界、并让后续槽位错位。"""
    b = pw.encode("utf-8", "replace")[:MAX_PW_LEN]
    return b, len(b)

# ===========================================================================
#  第零部分：颜色 / 终端 / 剪贴板 / 免责
# ===========================================================================

IS_TTY = sys.stdout.isatty()
_COLOR_OK = not os.environ.get("NO_COLOR")


class _C:
    """ANSI 颜色包装；--no-color / 重定向 / NO_COLOR 时全部退化为空串"""
    def __init__(self):
        self.enabled = False

    def init(self, no_color=False):
        self.enabled = (not no_color) and _COLOR_OK and IS_TTY
        if self.enabled and os.name == "nt":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass

    def _w(self, code):
        return "\x1b[%sm" % code if self.enabled else ""

    @property
    def R(self):    return self._w("0")
    @property
    def RED(self):  return self._w("31;1")
    @property
    def GRN(self):  return self._w("32;1")
    @property
    def YEL(self):  return self._w("33;1")
    @property
    def BLU(self):  return self._w("34;1")
    @property
    def CYN(self):  return self._w("36;1")
    @property
    def BLD(self):  return self._w("1")
    @property
    def DIM(self):  return self._w("2")


C = _C()


def cprint(msg, color=""):
    print("%s%s%s" % (color, msg, C.R))


def clipboard_copy(text):
    """把找到的密码写进系统剪贴板（尽力而为，失败静默）"""
    try:
        if os.name == "nt":
            import ctypes
            data = text.encode("utf-16-le") + b"\x00\x00"
            k32 = ctypes.windll.kernel32
            u32 = ctypes.windll.user32
            k32.Global.restype = ctypes.c_void_p
            h = k32.GlobalAlloc(0x0002, len(data))
            p = k32.GlobalLock(ctypes.c_void_p(h))
            ctypes.memmove(p, data, len(data))
            k32.GlobalUnlock(ctypes.c_void_p(h))
            if u32.OpenClipboard(0):
                u32.EmptyClipboard()
                u32.SetClipboardData(13, ctypes.c_void_p(h))   # CF_UNICODETEXT
                u32.CloseClipboard()
            return True
        if sys.platform == "darwin":
            import subprocess as sp
            sp.run(["pbcopy"], input=text.encode(), check=False)
            return True
        for tool, args in (("xclip", ("-selection", "clipboard",)),
                           ("xsel", ("--clipboard", "--input",))):
            if shutil.which(tool):
                subprocess.run([tool] + list(args), input=text.encode(), check=False)
                return True
    except Exception:
        pass
    return False


def human(t):
    t = int(t)
    h, r = divmod(t, 3600)
    m, s = divmod(r, 60)
    return ("%d小时%02d分%02d秒" % (h, m, s)) if h else ("%02d分%02d秒" % (m, s))


def _pause(msg="\n按回车退出..."):
    try:
        input(msg)
    except EOFError:
        pass


def _ask(msg):
    try:
        return input(msg)
    except EOFError:
        return ""


def _init_console():
    """让 stdout/stderr 遇到编码不了的字符时退化，而不是抛 UnicodeEncodeError。
    （GBK 控制台/重定向到文件时，✔ ✘ 等符号会直接崩掉汇总输出）"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def _say(text, newline=False):
    """进度行输出：终端里覆盖同一行，重定向到文件时逐行打印"""
    if IS_TTY and not newline:
        sys.stdout.write("\r" + text.ljust(100))
    else:
        sys.stdout.write(text + "\n")
    sys.stdout.flush()


# ===========================================================================
#  第一部分：依赖探测与自动安装（GPU / cryptography / msoffcrypto）
# ===========================================================================

# 驱动版本 -> 支持的 CUDA 大版本（粗粒度，够选 cupy 包用）
_DRIVER_TO_CUDA = (
    (580, 13), (575, 12), (525, 12), (450, 11),
)


def _driver_major(ver):
    try:
        return int(ver.split(".")[0])
    except Exception:
        return 0


def cuda_from_driver(driver_ver):
    m = _driver_major(driver_ver)
    if m >= 580:
        return 13
    if m >= 525:
        return 12
    if m >= 450:
        return 11
    return 0


def nvidia_smi_probe():
    """返回 (list[(name, driver, cc)], err)。没有 nvidia-smi 或无 N 卡时 err 有值"""
    exe = shutil.which("nvidia-smi")
    if not exe and os.name == "nt":
        for p in (r"C:\Windows\System32\nvidia-smi.exe",
                  r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"):
            if os.path.isfile(p):
                exe = p
                break
    if not exe:
        return [], "找不到 nvidia-smi（未安装 NVIDIA 驱动，或不是 NVIDIA 显卡）"
    try:
        out = subprocess.run(
            [exe, "--query-gpu=name,driver_version,compute_cap",
             "--format=csv,noheader"],
            capture_output=True, timeout=15)
        txt = out.stdout.decode("utf-8", "replace").strip()
        if not txt:
            return [], "nvidia-smi 没有返回任何 GPU（可能是纯核显机器）"
        gpus = []
        for line in txt.splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 3:
                gpus.append((parts[0], parts[1], parts[2]))
        return gpus, None
    except Exception as ex:
        return [], "nvidia-smi 执行失败: %r" % (ex,)


def cupy_package_for(cuda_major):
    if cuda_major >= 13:
        return "cupy-cuda13x", None
    if cuda_major == 12:
        return "cupy-cuda12x", None
    if cuda_major == 11:
        # CuPy 13 起不再发布 cuda11x 轮子，固定用最后的 11.x 支持版本
        return "cupy-cuda11x", "cupy-cuda11x==12.3.0"
    return None, None


def pip_install(pkgs, mirror=None, quiet=False):
    """用当前解释器的 pip 安装包。返回 (成功?, 输出)"""
    mirror = mirror or os.environ.get("BCRACK_MIRROR")
    murls = {
        "tuna": "https://pypi.tuna.tsinghua.edu.cn/simple",
        "aliyun": "https://mirrors.aliyun.com/pypi/simple/",
        "douban": "https://pypi.doubanio.com/simple/",
    }
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    if quiet:
        cmd.append("-q")
    if mirror:
        url = murls.get(mirror, mirror)
        cmd += ["-i", url]
    cmd += pkgs
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=1800)
        ok = r.returncode == 0
        out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
        return ok, out
    except Exception as ex:
        return False, str(ex)


def _pip_hint(mirror):
    murls = {
        "tuna": "https://pypi.tuna.tsinghua.edu.cn/simple",
        "aliyun": "https://mirrors.aliyun.com/pypi/simple/",
    }
    if mirror in murls:
        return " -i %s" % murls[mirror]
    return ""


def import_retry(modname):
    """pip 安装后同进程重新 import：清掉失败的模块缓存再试"""
    for m in list(sys.modules):
        if m == modname or m.startswith(modname + "."):
            del sys.modules[m]
    import importlib
    importlib.invalidate_caches()
    __import__(modname)


def try_import(modname):
    try:
        __import__(modname)
        return True
    except ImportError:
        return False


def maybe_install(modname, pkgs, why, mirror, auto_yes, assume_yes_default=False):
    """询问并自动安装可选依赖。返回 (可用?)"""
    if try_import(modname):
        return True
    if assume_yes_default and auto_yes is None:
        auto_yes = True
    if auto_yes is True:
        ans = "y"
    elif auto_yes is False:
        ans = "n"
    else:
        ans = _ask("%s\n    是否现在自动安装？(y/N) " % why).strip().lower()
    if ans not in ("y", "yes", "是"):
        return False
    print("  正在安装: pip install %s%s ..." % (" ".join(pkgs), _pip_hint(mirror)))
    ok, out = pip_install(pkgs, mirror)
    if not ok:
        print("  %s安装失败：%s" % (C.RED, out[-600:]))
        print("  %s可手动执行: pip install %s%s" % (C.YEL, " ".join(pkgs), _pip_hint(mirror)))
        return False
    if try_import(modname):
        return True
    try:
        import_retry(modname)
        return True
    except Exception as ex:
        print("  %s安装完成但导入失败：%r（可能装到了别的解释器）" % (C.YEL, ex))
        print("  当前解释器：%s" % sys.executable)
        return False


# ===========================================================================
#  第二部分：最小 CFB(OLE2) 读取器（支持上下文管理器 / 大小写不敏感流名）
# ===========================================================================

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE


class CFBError(Exception):
    pass


class CFBReader:
    """只读 MS-CFB 复合文档，用于取出 EncryptionInfo / EncryptedPackage 等流"""

    def __init__(self, path):
        self.f = open(path, "rb")
        hdr = self.f.read(512)
        if len(hdr) < 512 or hdr[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            self.f.close()
            raise CFBError("不是 CFB/OLE 复合文档（可能未加密）")
        self.sector_size = 1 << struct.unpack("<H", hdr[30:32])[0]
        self.mini_sector_size = 1 << struct.unpack("<H", hdr[32:34])[0]
        self.first_dir_sector = struct.unpack("<I", hdr[48:52])[0]
        self.mini_cutoff = struct.unpack("<I", hdr[56:60])[0]
        self.first_minifat = struct.unpack("<I", hdr[60:64])[0]
        self.first_difat = struct.unpack("<I", hdr[68:72])[0]

        # ---- DIFAT：定位所有 FAT 扇区 ----
        difat = list(struct.unpack("<109I", hdr[76:512]))
        sec, guard = self.first_difat, 0
        per = self.sector_size // 4 - 1
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 100000:
            vals = list(struct.unpack("<%dI" % (self.sector_size // 4),
                                      self._read_sector(sec)))
            difat.extend(vals[:per])
            sec = vals[per]
            guard += 1

        fat = []
        seen = set()
        for fs in difat:
            if fs in (FREESECT, ENDOFCHAIN) or fs in seen:
                continue
            seen.add(fs)
            fat.extend(struct.unpack("<%dI" % (self.sector_size // 4),
                                     self._read_sector(fs)))
        self.fat = fat

        # ---- miniFAT ----
        mf, sec, guard = [], self.first_minifat, 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 100000:
            mf.extend(struct.unpack("<%dI" % (self.sector_size // 4),
                                    self._read_sector(sec)))
            sec = self.fat[sec] if sec < len(self.fat) else ENDOFCHAIN
            guard += 1
        self.minifat = mf

        # ---- 目录项 ----
        self.dirents, self.root = [], None
        for ent in self._iter_dir_entries():
            self.dirents.append(ent)
            if ent["type"] == 5 and self.root is None:
                self.root = ent
        if self.root is None:
            self.close()
            raise CFBError("复合文档缺少 Root Entry")
        self.ministream = self._read_chain(self.root["start"], self.root["size"])

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- 底层 --
    def _read_sector(self, n):
        self.f.seek((n + 1) * self.sector_size)
        return self.f.read(self.sector_size)

    def _iter_dir_entries(self):
        sec, guard = self.first_dir_sector, 0
        while sec not in (ENDOFCHAIN, FREESECT) and guard < 100000:
            raw = self._read_sector(sec)
            for off in range(0, len(raw) - 127, 128):
                e = raw[off:off + 128]
                nlen = struct.unpack("<H", e[64:66])[0]
                name = e[:nlen - 2].decode("utf-16-le", "replace") if 2 <= nlen <= 64 else ""
                yield {
                    "name": name,
                    "type": e[66],
                    "start": struct.unpack("<I", e[116:120])[0],
                    "size": struct.unpack("<Q", e[120:128])[0],
                }
            sec = self.fat[sec] if sec < len(self.fat) else ENDOFCHAIN
            guard += 1

    def _read_chain(self, start, size):
        out, s, guard = bytearray(), start, 0
        while s not in (ENDOFCHAIN, FREESECT) and len(out) < size and guard < 10 ** 7:
            out += self._read_sector(s)
            s = self.fat[s] if s < len(self.fat) else ENDOFCHAIN
            guard += 1
        return bytes(out[:size])

    def _read_mini_chain(self, start, size):
        out, s, guard = bytearray(), start, 0
        while s not in (ENDOFCHAIN, FREESECT) and len(out) < size and guard < 10 ** 7:
            off = s * self.mini_sector_size
            out += self.ministream[off:off + self.mini_sector_size]
            s = self.minifat[s] if s < len(self.minifat) else ENDOFCHAIN
            guard += 1
        return bytes(out[:size])

    def _sane_package(self, data):
        """EncryptedPackage 首 8 字节为明文总长，据此判断读法是否合理"""
        if len(data) < 9:
            return False
        total = struct.unpack("<Q", data[:8])[0]
        rest = len(data) - 8
        return 0 < total <= rest and (rest - total) < 16

    def has_stream(self, name):
        name = name.lower()
        for e in self.dirents:
            if e["type"] == 2 and e["name"].lower() == name:
                return True
        return False

    def stream_names(self):
        return sorted(e["name"] for e in self.dirents if e["type"] == 2)

    def read_stream(self, name, smart_package=False):
        name = name.lower()   # MS-CFB 流名大小写不敏感
        for e in self.dirents:
            if e["type"] == 2 and e["name"].lower() == name:
                if e["size"] < self.mini_cutoff:
                    data = self._read_mini_chain(e["start"], e["size"])
                    # 某些写入器会把小尺寸 EncryptedPackage 放进常规扇区，
                    # 若按 mini 链读出的总长明显不合理，则改走 FAT 链
                    if smart_package and not self._sane_package(data):
                        alt = self._read_chain(e["start"], e["size"])
                        if self._sane_package(alt):
                            return alt
                    return data
                return self._read_chain(e["start"], e["size"])
        raise CFBError("找不到流: %s" % name)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ===========================================================================
#  第三部分：纯 Python AES（CBC/ECB 解密 + ECB 加密单块）/ RC4
#             （有 cryptography 时自动用 C 实现，速度快 50~100 倍）
# ===========================================================================

_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
_SBOX_INV = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _SBOX_INV[_v] = _i
_SBOX_INV = bytes(_SBOX_INV)

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def _mul(a, b):
    """GF(2^8) 乘法"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_td_tables():
    """解密用 T 表（已合并 InvSubBytes），T[r][k][x]"""
    M = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
    tabs = []
    for r in range(4):
        per = []
        for k in range(4):
            coef = M[k][r]
            per.append([_mul(s, coef) for s in _SBOX_INV])
        tabs.append(per)
    return tabs


TD = _build_td_tables()


def _inv_mix_columns(v):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = v[4 * c:4 * c + 4]
        out[4 * c] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        out[4 * c + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        out[4 * c + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        out[4 * c + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    return bytes(out)


def _expand_key(key, dec_prep=True):
    """AES 密钥扩展。dec_prep=True 时对中间轮密钥做 InvMixColumns 预处理"""
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        prev = w[i - nk]
        w.append([prev[j] ^ t[j] for j in range(4)])
    flat = []
    for word in w:
        flat.extend(word)
    rk = bytes(flat)
    if not dec_prep:
        return rk
    parts = [rk[:16]]
    for r in range(1, nr):
        parts.append(_inv_mix_columns(rk[16 * r:16 * r + 16]))
    parts.append(rk[nr * 16:])
    return b"".join(parts)


def aes_decrypt_block(ct, rk):
    """解密单个 16 字节块（不做 CBC 链接）。rk 为 _expand_key 结果。"""
    nr = len(rk) // 16 - 1
    s = [ct[i] ^ rk[nr * 16 + i] for i in range(16)]
    for rnd in range(nr - 1, 0, -1):
        off = rnd * 16
        t0, t1, t2, t3 = TD[0], TD[1], TD[2], TD[3]
        ns = [0] * 16
        for c in range(4):
            b0 = s[4 * c]
            b1 = s[4 * ((c - 1) & 3) + 1]
            b2 = s[4 * ((c - 2) & 3) + 2]
            b3 = s[4 * ((c - 3) & 3) + 3]
            u0, u1, u2, u3 = t0[0][b0], t1[0][b1], t2[0][b2], t3[0][b3]
            v0, v1, v2, v3 = t0[1][b0], t1[1][b1], t2[1][b2], t3[1][b3]
            w0, w1, w2, w3 = t0[2][b0], t1[2][b1], t2[2][b2], t3[2][b3]
            x0, x1, x2, x3 = t0[3][b0], t1[3][b1], t2[3][b2], t3[3][b3]
            o = 4 * c
            ns[o]     = u0 ^ u1 ^ u2 ^ u3 ^ rk[off + o]
            ns[o + 1] = v0 ^ v1 ^ v2 ^ v3 ^ rk[off + o + 1]
            ns[o + 2] = w0 ^ w1 ^ w2 ^ w3 ^ rk[off + o + 2]
            ns[o + 3] = x0 ^ x1 ^ x2 ^ x3 ^ rk[off + o + 3]
        s = ns
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = _SBOX_INV[s[4 * ((c - r) & 3) + r]] ^ rk[4 * c + r]
    return bytes(out)


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        out[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
    return out


def aes_encrypt_block(pt, key):
    """加密单个 16 字节块（ECB）。PDF R6 密钥推导需要。"""
    rk = _expand_key(key, dec_prep=False)
    nr = len(rk) // 16 - 1
    s = [pt[i] ^ rk[i] for i in range(16)]
    for rnd in range(1, nr):
        t = [_SBOX[b] for b in s]
        # ShiftRows
        t = [t[4 * ((c + r) & 3) + r] for c in range(4) for r in range(4)]
        t = _mix_columns(t)
        off = rnd * 16
        s = [t[i] ^ rk[off + i] for i in range(16)]
    t = [_SBOX[b] for b in s]
    t = [t[4 * ((c + r) & 3) + r] for c in range(4) for r in range(4)]
    return bytes(t[i] ^ rk[nr * 16 + i] for i in range(16))


def aes_cbc_decrypt_first_block(ct, key, iv):
    """CBC 只解出第一个明文块（破解校验最常用）"""
    rk = _expand_key(key)
    return bytes(a ^ b for a, b in zip(aes_decrypt_block(ct[:16], rk), iv[:16]))


def aes_cbc_decrypt(data, key, iv):
    """完整 CBC 解密（纯 Python 慢路径；大文件优先用 cryptography）"""
    rk = _expand_key(key)
    out = bytearray()
    prev = iv[:16]
    for off in range(0, len(data) - len(data) % 16, 16):
        blk = aes_decrypt_block(data[off:off + 16], rk)
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[off:off + 16]
    return bytes(out)


def aes_ecb_decrypt(data, key):
    """完整 ECB 解密（Standard 加密用于校验）"""
    rk = _expand_key(key)
    out = bytearray()
    for off in range(0, len(data) - len(data) % 16, 16):
        out += aes_decrypt_block(data[off:off + 16], rk)
    return bytes(out)


def rc4_crypt(key, data):
    """RC4 流密码（加解密同一操作）"""
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(ch ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# ---- cryptography 加速封装（可用时自动替换慢路径）----

_CRYPTO_OK = None


def has_crypto():
    global _CRYPTO_OK
    if _CRYPTO_OK is None:
        _CRYPTO_OK = try_import("cryptography")
    return _CRYPTO_OK


def fast_cbc_decrypt(data, key, iv, unpadded=False):
    """完整 CBC 解密：有 cryptography 走 C 实现，否则纯 Python"""
    if has_crypto():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.CBC(iv[:16]))
        d = c.decryptor()
        out = d.update(bytes(data)) + d.finalize()
        return out
    return aes_cbc_decrypt(data, key, iv)


def fast_ecb_decrypt(data, key):
    if has_crypto():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.ECB())
        d = c.decryptor()
        return d.update(bytes(data)) + d.finalize()
    return aes_ecb_decrypt(data, key)


def fast_cbc_encrypt(data, key, iv):
    """CBC 加密（PDF R6 需要；无 cryptography 时用纯 Python 单块循环）"""
    if has_crypto():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.CBC(iv[:16]))
        e = c.encryptor()
        return e.update(bytes(data)) + e.finalize()
    rk = _expand_key(key, dec_prep=False)
    out, prev = bytearray(), iv[:16]
    for off in range(0, len(data) - len(data) % 16, 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        cur = aes_encrypt_block(blk, key)
        out += cur
        prev = cur
    return bytes(out)

# ===========================================================================
#  第四部分：Office 加密参数解析与密码校验（Agile / Standard / XOR）
# ===========================================================================

import xml.etree.ElementTree as ET   # noqa: E402（模块级统一导入）

HASHERS = {
    "SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384, "SHA512": hashlib.sha512,
}
HASHLEN = {"SHA1": 20, "SHA256": 32, "SHA384": 48, "SHA512": 64}
BLK_VERIFIER = bytes([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
BLK_VERIFIER_HASH = bytes([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])
BLK_KEY_VALUE = bytes([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
BLK_DATA_INTEGRITY1 = bytes([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
BLK_DATA_INTEGRITY2 = bytes([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])


def parse_agile(ei_bytes):
    """解析 EncryptionInfo（Agile 模式）"""
    if len(ei_bytes) < 12 or struct.unpack("<HH", ei_bytes[:4]) != (4, 4):
        return None
    try:
        ns = {"e": "http://schemas.microsoft.com/office/2006/encryption",
              "p": "http://schemas.microsoft.com/office/2006/keyEncryptor/password"}
        root = ET.fromstring(ei_bytes[8:].decode("utf-8", "replace"))
        kd = root.find("e:keyData", ns)
        ek = root.find("e:keyEncryptors/e:keyEncryptor/p:encryptedKey", ns)
        if kd is None or ek is None:
            return None
        d = base64.b64decode
        return {
            "keyDataSalt": d(kd.attrib["saltValue"]),
            "keyDataAlg": kd.attrib.get("hashAlgorithm", "SHA512").upper(),
            "keyDataKeyBits": int(kd.attrib.get("keyBits", 256)),
            "salt": d(ek.attrib["saltValue"]),
            "spin": int(ek.attrib["spinCount"]),
            "alg": ek.attrib.get("hashAlgorithm", "SHA512").upper(),
            "keyBits": int(ek.attrib.get("keyBits", 256)),
            "blockSize": int(ek.attrib.get("blockSize", 16)),
            "encVerifierInput": d(ek.attrib["encryptedVerifierHashInput"]),
            "encVerifierHash": d(ek.attrib["encryptedVerifierHashValue"]),
            "encKeyValue": d(ek.attrib["encryptedKeyValue"]),
            "cipher": ek.attrib.get("cipherAlgorithm", "AES").upper(),
        }
    except Exception:
        return None


def parse_standard(ei_bytes):
    """解析 EncryptionInfo（Standard / CryptoAPI 模式，二进制结构）。
    v1.2: salt 大小不再硬编码 16 字节，按实际 saltSize 读取。"""
    try:
        if len(ei_bytes) < 12:
            return None
        ver = struct.unpack("<HH", ei_bytes[:4])
        if ver[0] not in (2, 3, 4):
            return None
        flags = struct.unpack("<I", ei_bytes[4:8])[0]
        if not (flags & 0x04):          # 0x04 = CryptoAPI 标志
            return None
        hsize = struct.unpack("<I", ei_bytes[8:12])[0]
        if hsize < 32:
            return None
        alg_id = struct.unpack("<I", ei_bytes[20:24])[0]
        alg_hash = struct.unpack("<I", ei_bytes[24:28])[0]
        key_size = struct.unpack("<I", ei_bytes[28:32])[0]
        v = 12 + hsize
        if len(ei_bytes) < v + 8:
            return None
        salt_size = struct.unpack("<I", ei_bytes[v:v + 4])[0]
        if not (4 <= salt_size <= 64):
            return None
        off = v + 4
        salt = ei_bytes[off:off + salt_size]
        off += salt_size
        if len(ei_bytes) < off + 20:
            return None
        enc_verifier = ei_bytes[off:off + 16]
        off += 16
        ver_hash_size = struct.unpack("<I", ei_bytes[off:off + 4])[0]
        off += 4
        if not (16 <= ver_hash_size <= 64):
            ver_hash_size = 20
        enc_verifier_hash = ei_bytes[off:off + ver_hash_size * 2]
        if key_size % 8 or not (5 <= key_size // 8 <= 32):   # RC4-40 key 为 5 字节
            return None
        return {
            "algId": alg_id, "algIdHash": alg_hash, "keySize": key_size,
            "spin": 50000, "salt": salt, "verMajor": ver[0],
            "encVerifier": enc_verifier, "encVerifierHash": enc_verifier_hash,
            "cipher": "RC4" if alg_id in (0x6801, 0x6802) else "AES",
        }
    except Exception:
        return None


# ---- Office 97-2003 XOR 混淆（[MS-OFFCRYPTO] 2.3.7，常量按规范） ----

_XOR_PAD = bytes([
    0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00,
    0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
])
_XOR_INIT = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
    0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
]
_XOR_MATRIX = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61,
    0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF, 0x4563, 0x8AC6,
    0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4,
    0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E,
    0x553D, 0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496,
    0x390D, 0x721A, 0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC,
    0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
    0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0,
    0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483,
    0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1,
    0x85C3, 0x1BA7, 0x374E, 0x6E9C, 0x3730, 0x6E60, 0xDCC0, 0xA9A1,
    0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373,
    0x06E6, 0x0DCC, 0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462,
    0x48C4,
]


def _ror8(v, n):
    return ((v >> n) | (v << (8 - n))) & 0xFF


def _xor_ror(b1, b2):
    return _ror8(b1 ^ b2, 1)


def xor_key_method1(pw):
    """CreateXorKey_Method1：密码 -> 16 位 XOR key"""
    key = _XOR_INIT[len(pw) - 1]
    cur = 0x68
    for ch in reversed(pw.encode("latin-1", "replace")):
        for _ in range(7):
            if ch & 0x40:
                key ^= _XOR_MATRIX[cur]
            ch = (ch << 1) & 0xFF
            cur -= 1
    return key & 0xFFFF


def xor_array_method1(pw):
    """CreateXorArray_Method1：密码 -> 16 字节混淆数组"""
    xor_key = xor_key_method1(pw)
    pw_b = pw.encode("latin-1", "replace")
    n = len(pw)
    arr = [0] * 16
    index = n
    if index % 2 == 1:
        temp = (xor_key & 0xFF00) >> 8
        arr[index] = _xor_ror(_XOR_PAD[0], temp)
        index -= 1
        temp = xor_key & 0xFF
        arr[index] = _xor_ror(pw_b[-1], temp)
    while index > 0:
        index -= 1
        temp = (xor_key & 0xFF00) >> 8
        arr[index] = _xor_ror(pw_b[index], temp)
        index -= 1
        temp = xor_key & 0xFF
        arr[index] = _xor_ror(pw_b[index], temp)
    index = 15
    pad_index = 15 - n
    while pad_index > 0:
        temp = (xor_key & 0xFF00) >> 8
        arr[index] = _xor_ror(_XOR_PAD[pad_index], temp)
        index -= 1
        pad_index -= 1
        temp = xor_key & 0xFF
        arr[index] = _xor_ror(_XOR_PAD[pad_index], temp)
        index -= 1
        pad_index -= 1
    return arr


def xor_transform(data, pw, base=0):
    """DecryptData_Method1: value = ror(byte ^ xor_array[i%16], 5)"""
    arr = xor_array_method1(pw)
    out = bytearray(len(data))
    for i, v in enumerate(data):
        out[i] = _ror8(v ^ arr[(base + i) % 16], 5)
    return bytes(out)


def verify_xor_doc(pw, params):
    """XOR 混淆 .doc 校验：解密 FIB 头，检查 wIdent/nFib。
    params: {'fib_head': 加密的 WordDocument 流前 16 字节}"""
    try:
        dec = xor_transform(params["fib_head"][:16], pw)
        w_ident = struct.unpack(">H", dec[0:2])[0]
        n_fib = struct.unpack(">H", dec[2:4])[0]
        return w_ident == 0xA5EC and 0x00C1 <= n_fib <= 0x00E1
    except Exception:
        return False


# ---- Agile / Standard 校验 ----

B36 = b"\x36" * 64
B5C = b"\x5c" * 64


def derive_std_key_from_h(h, key_size_bytes):
    """Standard 密钥派生后半段（输入迭代后的中间哈希）"""
    hf = hashlib.sha1(h + b"\x00\x00\x00\x00").digest()
    b1 = bytearray(B36)
    b1[:20] = bytes(a ^ b for a, b in zip(hf, B36[:20]))
    x1 = hashlib.sha1(bytes(b1)).digest()
    b2 = bytearray(B5C)
    b2[:20] = bytes(a ^ b for a, b in zip(hf, B5C[:20]))
    x2 = hashlib.sha1(bytes(b2)).digest()
    return (x1 + x2)[:key_size_bytes]


def verify_std_fast(pw, p):
    """Standard 加密的密码校验"""
    h = hashlib.sha1(p["salt"] + pw.encode("utf-16-le")).digest()
    for i in range(p["spin"]):
        h = hashlib.sha1(struct.pack("<I", i) + h).digest()
    key = derive_std_key_from_h(h, p["keySize"] // 8)
    if p["cipher"] == "RC4":
        verifier = rc4_crypt(key, p["encVerifier"])
        expected = hashlib.sha1(verifier).digest()
        got = rc4_crypt(key, p["encVerifierHash"])[:20]
    else:
        verifier = fast_ecb_decrypt(p["encVerifier"], key)
        expected = hashlib.sha1(verifier).digest()
        got = fast_ecb_decrypt(p["encVerifierHash"], key)[:20]
    return expected == got


def first_iterate(pw, salt, spin, hasher):
    """Agile KDF 迭代链，返回最终 hash（bytes）"""
    h = hasher(salt + pw.encode("utf-16-le")).digest()
    for i in range(spin):
        x = hasher(struct.pack("<I", i))
        x.update(h)
        h = x.digest()
    return h


def verify_password_fast(pw, salt, spin, hasher, keylen, evi, evh):
    """快速校验（只解 1 块 + 比 16 字节）"""
    h = first_iterate(pw, salt, spin, hasher)
    k1 = hasher(h + BLK_VERIFIER).digest()[:keylen]
    vin = aes_cbc_decrypt_first_block(evi, k1, salt)
    actual = hasher(vin).digest()
    k2 = hasher(h + BLK_VERIFIER_HASH).digest()[:keylen]
    expected = aes_cbc_decrypt_first_block(evh, k2, salt)
    return actual[:16] == expected[:16]


def derive_secret_key(password, p):
    """由密码派生 secretKey（用于解密正文）"""
    hasher = HASHERS[p["alg"]]
    h = first_iterate(password, p["salt"], p["spin"], hasher)
    key3 = hasher(h + BLK_KEY_VALUE).digest()[: p["keyBits"] // 8]
    return fast_cbc_decrypt(p["encKeyValue"], key3, p["salt"])


# ===========================================================================
#  第五部分：PDF 加密（R2/R3/R4: RC4/AES-128；R6: AES-256）
# ===========================================================================

PDF_PAD = bytes([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
    0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
])


def _pdf_find_dict_blob(buf):
    """在缓冲里找到第一处平衡的 << ... >>，返回 (start, end)。失败返回 None"""
    i = buf.find(b"<<")
    while i >= 0:
        depth, j = 0, i
        while j < len(buf) - 1:
            if buf[j:j + 2] == b"<<":
                depth += 1
                j += 2
            elif buf[j:j + 2] == b">>":
                depth -= 1
                j += 2
                if depth == 0:
                    return i, j
            elif buf[j:j + 1] == b"(":
                # 跳过字面字符串（处理转义和嵌套括号）
                j += 1
                pdepth = 1
                while j < len(buf) and pdepth:
                    if buf[j:j + 1] == b"\\":
                        j += 2
                        continue
                    if buf[j:j + 1] == b"(":
                        pdepth += 1
                    elif buf[j:j + 1] == b")":
                        pdepth -= 1
                    j += 1
            else:
                j += 1
        i = buf.find(b"<<", i + 2)
    return None


def _pdf_token(buf, i):
    """从 i 处读一个 PDF 对象 token。返回 (kind, value, next_i)
    kind: 'name' 'num' 'str' 'hex' 'arr' 'dict' 'kw' """
    n = len(buf)
    while i < n and buf[i:i + 1] in b" \t\r\n\x00":
        i += 1
    if i >= n:
        return None, None, i
    c = buf[i:i + 1]
    if c == b"/":
        j = i + 1
        while j < n and buf[j:j + 1] not in b" \t\r\n\x00/[]<>()":
            j += 1
        return "name", buf[i + 1:j].decode("latin-1"), j
    if c == b"(":
        j, pdepth = i + 1, 1
        while j < n and pdepth:
            if buf[j:j + 1] == b"\\":
                j += 2
                continue
            if buf[j:j + 1] == b"(":
                pdepth += 1
            elif buf[j:j + 1] == b")":
                pdepth -= 1
            j += 1
        return "str", buf[i + 1:j - 1], j
    if c == b"<" and buf[i + 1:i + 2] != b"<":
        j = buf.find(b">", i)
        if j < 0:
            j = n
        htxt = buf[i + 1:j].replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
        if len(htxt) % 2:
            htxt += b"0"
        try:
            return "hex", bytes.fromhex(htxt.decode("ascii")), j + 1
        except Exception:
            return "hex", b"", j + 1
    if c == b"[":
        return "arr", b"[", i + 1
    if c == b"]":
        return "arr", b"]", i + 1
    if buf[i:i + 2] == b"<<":
        return "dict", b"<<", i + 2
    if buf[i:i + 2] == b">>":
        return "dict", b">>", i + 2
    if c == b"-" or c.isdigit():
        j = i
        if c == b"-":
            j += 1
        while j < n and (buf[j:j + 1].isdigit() or buf[j:j + 1] in b".-"):
            if buf[j:j + 1] == b"-" and j > i:
                break
            j += 1
        txt = buf[i:j].decode("latin-1")
        try:
            return "num", (float(txt) if "." in txt else int(txt)), j
        except ValueError:
            return "kw", txt, j
    j = i
    while j < n and buf[j:j + 1] not in b" \t\r\n\x00/[]<>()":
        j += 1
    if j == i:
        j += 1
    return "kw", buf[i:j].decode("latin-1"), j


def _pdf_parse_dict(buf, start):
    """解析 start 处开始的 dict 内容（<< 已跳过），返回 (dict, end_i)。
    值：标量直接存；嵌套 dict 存 dict；R 引用返回 (num, gen, 'R')。"""
    out = {}
    i = start
    while True:
        kind, val, i = _pdf_token(buf, i)
        if kind is None or kind == "dict" and val == b">>":
            return out, i
        if kind != "name":
            continue
        kind2, val2, i2 = _pdf_token(buf, i)
        if kind2 in (None,):
            return out, i2
        if kind2 == "dict" and val2 == b"<<":
            sub, i = _pdf_parse_dict(buf, i2)
            out[val] = sub
        elif kind2 == "arr":
            i = i2
            lst = []
            while True:
                k3, v3, i3 = _pdf_token(buf, i)
                if k3 is None or (k3 == "arr" and v3 == b"]"):
                    i = i3
                    break
                if k3 == "arr" and v3 == b"[":
                    i = i3
                    continue
                if k3 == "dict" and v3 == b"<<":
                    sub, i3 = _pdf_parse_dict(buf, i3)
                    lst.append(sub)
                    i = i3
                    continue
                if k3 == "dict" and v3 == b">>":
                    i = i3
                    break
                # R 引用: num num R
                if k3 == "num":
                    k4, v4, i4 = _pdf_token(buf, i3)
                    if k4 == "num":
                        k5, v5, i5 = _pdf_token(buf, i4)
                        if k5 == "kw" and v5 == "R":
                            lst.append((v3, v4, "R"))
                            i = i5
                            continue
                        lst.append(v3)
                        i = i3
                        continue
                    lst.append(v3)
                    i = i3
                    continue
                lst.append(v3)
                i = i3
            out[val] = lst
        else:
            # 可能是 R 引用
            if kind2 == "num":
                k3, v3, i3 = _pdf_token(buf, i2)
                if k3 == "num":
                    k4, v4, i4 = _pdf_token(buf, i3)
                    if k4 == "kw" and v4 == "R":
                        out[val] = (val2, v3, "R")
                        i = i4
                        continue
            out[val] = val2
            i = i2


def parse_pdf(path):
    """解析 PDF 加密字典。返回 (kind, params) 或 (None, err)。
    kind: 'pdf_r2' 'pdf_r3' 'pdf_r4_aes' 'pdf_r6'"""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 4096))
            tail = f.read()
        m = re.findall(rb"startxref\s+(\d+)", tail)
        if not m:
            return None, "找不到 startxref（不是标准 PDF？）"
        xref_off = int(m[-1])
        with open(path, "rb") as f:
            f.seek(xref_off)
            seg = f.read(8192)
        # 拿 trailer dict（传统 xref 表或 xref stream 的对象 dict）
        if seg.startswith(b"xref"):
            tb = seg.find(b"trailer")
            if tb < 0:
                return None, "xref 表后没有 trailer"
            blob = seg[tb + 8:]
        else:
            blob = seg[seg.find(b"obj"):] if b"obj" in seg[:64] else seg
        rng = _pdf_find_dict_blob(blob)
        if not rng:
            return None, "trailer dict 解析失败"
        trailer, _ = _pdf_parse_dict(blob, blob.find(b"<<", rng[0]) + 2)
        if "Encrypt" not in trailer:
            return None, "文档未加密（trailer 无 /Encrypt）"
        enc = trailer["Encrypt"]
        with open(path, "rb") as f:
            whole = f.read() if size < 64 * 1024 * 1024 else None
        if isinstance(enc, tuple) and len(enc) == 3 and enc[2] == "R":
            # 间接引用：全文件搜 "N G obj"
            key = b"%d %d obj" % (enc[0], enc[1])
            if whole is None:
                with open(path, "rb") as f:
                    whole = f.read()
            pos = whole.find(key)
            if pos < 0:
                return None, "找不到 Encrypt 间接对象"
            blob2 = whole[pos:pos + 8192]
            rng2 = _pdf_find_dict_blob(blob2)
            if not rng2:
                return None, "Encrypt 对象 dict 解析失败"
            edict, _ = _pdf_parse_dict(blob2, blob2.find(b"<<", rng2[0]) + 2)
        elif isinstance(enc, dict):
            edict = enc
        else:
            return None, "/Encrypt 格式无法识别"

        V = int(edict.get("V", 1))
        R = int(edict.get("R", 2))
        P = int(edict.get("P", -1))
        O = edict.get("O", b"")
        U = edict.get("U", b"")
        if isinstance(O, str):
            O = O.encode("latin-1")
        if isinstance(U, str):
            U = U.encode("latin-1")
        length = int(edict.get("Length", 40))
        enc_meta = edict.get("EncryptMetadata", True)
        if isinstance(enc_meta, str) and enc_meta == "false":
            enc_meta = False
        ID0 = b""
        ids = trailer.get("ID", [])
        if ids and isinstance(ids, list) and ids:
            first = ids[0]
            if isinstance(first, (bytes, bytearray)):
                ID0 = bytes(first)
            elif isinstance(first, str):
                ID0 = first.encode("latin-1")
        params = {"V": V, "R": R, "P": P, "O": O, "U": U, "length": length,
                  "id0": ID0, "enc_meta": bool(enc_meta)}

        if V >= 5 or R >= 5:
            if R == 5:
                return None, "PDF R5 (AES-256 ExtLevel3) 很罕见且已废弃，暂不支持；建议先转 R6 或联系工具作者"
            OE = edict.get("OE", b"")
            UE = edict.get("UE", b"")
            if isinstance(OE, str):
                OE = OE.encode("latin-1")
            if isinstance(UE, str):
                UE = UE.encode("latin-1")
            params.update({"OE": OE, "UE": UE})
            if len(U) < 48 or len(O) < 48:
                return None, "/U /O 长度异常（R6 应为 48 字节）"
            return "pdf_r6", params
        # V<=4: 确认流加密方式（RC4 或 AESV2）
        cfm = None
        cf = edict.get("CF")
        if isinstance(cf, dict):
            stdf = cf.get("StdCF")
            if isinstance(stdf, dict):
                cfm = stdf.get("CFM", "V2")
        stmf = edict.get("StmF", "StdF")
        if cfm is None and V == 4:
            cfm = "V2"
        n = max(5, length // 8) if V >= 2 else 5   # V=2 起按 Length 取钥长
        if R == 2:
            return "pdf_r2", dict(params, n=n)
        if cfm in ("AESV2",):
            return "pdf_r4_aes", dict(params, n=16)
        if cfm in ("AESV3",):
            return None, "AESV3 出现在 R<5 的加密里，格式异常"
        return "pdf_r3", dict(params, n=n)
    except Exception as ex:
        return None, "PDF 解析出错: %r" % (ex,)


def pdf_r6_hash(password_bytes, salt, udata):
    """PDF 2.0 Algorithm 2.B：R6 密码哈希（k1 重复 64 次 + SHA-256/384/512 轮换，
    退出条件按密文 E 末字节；实现与 qpdf/pypdf 对拍一致）"""
    pw = password_bytes[:127]
    K = hashlib.sha256(pw + salt + udata).digest()
    round_num = 0
    while True:
        round_num += 1
        E = fast_cbc_encrypt((pw + K + udata) * 64, K[0:16], K[16:32])
        idx = sum(E[:16]) % 3
        hasher = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[idx]
        K = hasher(E).digest()
        if round_num >= 64 and E[-1] <= (round_num - 32):
            break
        if round_num > 512:
            break
    return K[:32]


def verify_pdf_r6(pw, p):
    """R6 密码校验（Algorithm 2.A）：
    user:  Hash(pw, U_val_salt=U[32:40], udata=b"") == U[0:32]
    owner: Hash(pw, O_val_salt=O[32:40], udata=b"") == O[0:32]，
           中间密钥 = Hash(pw, O_key_salt=O[40:48], b"")，用于解 UE"""
    try:
        pw_b = pw.encode("utf-8")[:127]
        U = p["U"]
        if pdf_r6_hash(pw_b, U[32:40], b"") == U[0:32]:
            return True
        O = p["O"]
        if len(O) < 48 or len(p.get("UE", b"")) < 32:
            return False
        if pdf_r6_hash(pw_b, O[32:40], b"") != O[0:32]:
            return False
        # owner 密码正确：用中间密钥解 UE 得文件密钥
        try:
            ks = pdf_r6_hash(pw_b, O[40:48], b"")
            fast_cbc_decrypt(p["UE"][:32], ks, bytes(16))
            return True
        except Exception:
            return False
    except Exception:
        return False


def _pdf_r234_key(pw, p):
    """R2/R3/R4 密钥推导（Algorithm 3.2，MD5）"""
    pw_b = pw.encode("latin-1", "replace")[:32]
    m = hashlib.md5()
    m.update((pw_b + PDF_PAD)[:32])          # pad/truncate 到 32 字节
    m.update(p["O"])
    m.update(struct.pack("<I", p["P"]))      # P 无条件参与（u32 低字节在前）
    m.update(p["id0"])                       # ID 第一元素完整传入（不截 16）
    if p["R"] >= 4 and not p["enc_meta"]:
        m.update(b"\xff\xff\xff\xff")        # 4 字节（规范原文）
    key = m.digest()[:p["n"]]
    if p["R"] >= 3:
        for _ in range(50):                  # 只喂前 n 字节，不带 padding
            key = hashlib.md5(key).digest()[:p["n"]]
    return key


def verify_pdf_rc4(pw, p):
    """R2/R3/R4(RC4) 用户密码校验"""
    key = _pdf_r234_key(pw, p)
    if p["R"] == 2:
        return rc4_crypt(key, PDF_PAD) == p["U"][:32]
    # R3/R4(RC4)：U = RC4(key, MD5(padding+id0)[:16])，再 19 轮变钥（Algorithm 3.5）
    x = hashlib.md5(PDF_PAD + p["id0"]).digest()[:16]
    u = rc4_crypt(key, x)
    for i in range(1, 20):
        u = rc4_crypt(bytes(b ^ i for b in key), u)
    return u[:16] == p["U"][:16]


def verify_pdf_aesv2(pw, p):
    """R4 (AES-128) 用户密码校验：U = IV16 || AES-CBC(key, pad)"""
    key = _pdf_r234_key(pw, p)
    U = p["U"]
    if len(U) < 32:
        return False
    dec = fast_cbc_decrypt(U[16:32], key, U[0:16])
    return dec[:16] == PDF_PAD


# ===========================================================================
#  第六部分：ZIP 加密（ZipCrypto / WinZip AES）
# ===========================================================================

_AES_SALT_LEN = {1: 8, 2: 12, 3: 16}
_AES_KEY_LEN = {1: 16, 2: 24, 3: 32}


def _zip_read_local_header(zf, zinfo):
    """读取条目 local header 之后的原始数据起点信息。
    返回 (data_offset, local_extra) 或 (None, None)"""
    try:
        with open(zf.filename, "rb") as f:
            f.seek(zinfo.header_offset)
            hdr = f.read(30)
            if hdr[:4] != b"PK\x03\x04":
                return None, None
            nlen, elen = struct.unpack("<HH", hdr[26:30])
            name_and_extra = f.read(nlen + elen)
            extra = name_and_extra[nlen:]
            return f.tell(), extra
    except Exception:
        return None, None


def _parse_aes_extra(extra):
    """在 extra 字段里找 WinZip AES (0x9901)。返回 strength (1/2/3) 或 None。
    字段结构：header id(2) size(2) version(2) vendor(2) strength(1) method(2)"""
    i = 0
    while i + 4 <= len(extra):
        hid, sz = struct.unpack("<HH", extra[i:i + 4])
        body = extra[i + 4:i + 4 + sz]
        if hid == 0x9901 and len(body) >= 7:
            s = body[4]
            if s in (1, 2, 3):
                return s
        i += 4 + sz
    return None


def parse_zip(path):
    """解析 ZIP 加密信息。返回 (kind, params) 或 (None, err)"""
    try:
        with zipfile.ZipFile(path) as zf:
            for zinfo in zf.infolist():
                if not (zinfo.flag_bits & 0x1):
                    continue
                data_off, extra = _zip_read_local_header(zf, zinfo)
                if data_off is None:
                    continue
                # local extra 里也带 0x9901
                strength = _parse_aes_extra(extra)
                if strength is None:
                    strength = _parse_aes_extra(zinfo.extra)
                if strength in (1, 2, 3):
                    with open(path, "rb") as f:
                        f.seek(data_off)
                        salt_len = _AES_SALT_LEN[strength]
                        head = f.read(salt_len + 2)
                    if len(head) < salt_len + 2:
                        return None, "AES 头读取失败"
                    return "zip_aes", {
                        "salt": head[:salt_len], "verifier": head[salt_len:salt_len + 2],
                        "keybits": _AES_KEY_LEN[strength], "strength": strength,
                        "first_name": zinfo.filename, "data_off": data_off,
                        "csize": zinfo.compress_size, "_path": path,
                        "crc": zinfo.CRC, "flag": zinfo.flag_bits,
                        "time": zinfo.date_time,
                    }
                # ZipCrypto：前 12 字节为加密头
                with open(path, "rb") as f:
                    f.seek(data_off)
                    head = f.read(12)
                if len(head) < 12:
                    return None, "加密头读取失败"
                return "zip_crypto", {
                    "head": head, "crc": zinfo.CRC, "flag": zinfo.flag_bits,
                    "dos_time": (zinfo.date_time[3] << 11) | (zinfo.date_time[4] << 5) | (zinfo.date_time[5] // 2),
                    "first_name": zinfo.filename, "_path": path,
                }
            return None, "该 ZIP 没有加密条目"
    except zipfile.BadZipFile:
        return None, "不是合法的 ZIP 文件"
    except Exception as ex:
        return None, "ZIP 解析出错: %r" % (ex,)


def _zcrypto_stream_byte(key2):
    temp = (key2 | 2) & 0xFFFF
    return ((temp * (temp ^ 1)) >> 8) & 0xFF


# ZipCrypto 状态机用“原始 CRC32 更新原语”（无 zlib.crc32 的首尾取反语义！）
# zlib.crc32(x, prev) 的 prev 是上次返回值，语义不同；与 zipfile/qpdf 对拍后改用查表
_ZCRC_TABLE = None


def _zcrc_prim(ch, crc):
    global _ZCRC_TABLE
    if _ZCRC_TABLE is None:
        tbl = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
            tbl.append(c)
        _ZCRC_TABLE = tbl
    return (crc >> 8) ^ _ZCRC_TABLE[(crc ^ ch) & 0xFF]


def _zcrypto_update(key0, key1, key2, b):
    key0 = _zcrc_prim(b, key0) & 0xFFFFFFFF
    key1 = (key1 + (key0 & 0xFF)) & 0xFFFFFFFF
    key1 = (key1 * 134775813 + 1) & 0xFFFFFFFF
    key2 = _zcrc_prim((key1 >> 24) & 0xFF, key2) & 0xFFFFFFFF
    return key0, key1, key2


def verify_zip_crypto(pw, p):
    """ZipCrypto 密码校验：解密 12 字节头，比对 check byte"""
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in pw.encode("utf-8"):
        k0, k1, k2 = _zcrypto_update(k0, k1, k2, b)
    out = bytearray()
    for c in p["head"]:
        d = c ^ _zcrypto_stream_byte(k2)
        out.append(d)
        # ZipCrypto 状态机始终以“明文”字节推进（解密时 d 即明文）
        k0, k1, k2 = _zcrypto_update(k0, k1, k2, d)
    if p["flag"] & 0x8:
        # 流式写入（data descriptor）：check byte = DOS 时间高位
        return out[11] == ((p["dos_time"] >> 8) & 0xFF)
    return out[10] == ((p["crc"] >> 16) & 0xFF) and out[11] == ((p["crc"] >> 24) & 0xFF)


def verify_zip_aes(pw, p):
    """WinZip AES 密码校验：PBKDF2-HMAC-SHA1 1000 轮"""
    key = hashlib.pbkdf2_hmac("sha1", pw.encode("utf-8"), p["salt"], 1000,
                              2 * p["keybits"] + 2)
    return key[-2:] == p["verifier"]


# ---- ZIP 命中后的强验证（弱校验位只有 1/65536 置信度，大空间必出假阳性，
#      worker 端弱校验通过后必须完整解密复核，失败则继续扫，绝不停在假密码上）----

def confirm_zip_crypto(pw, p):
    """ZipCrypto 强验证：zipfile 完整解压（内含 CRC32 自动比对）"""
    try:
        with zipfile.ZipFile(p["_path"]) as zf:
            zf.read(p["first_name"], pwd=pw.encode("utf-8"))
        return True
    except Exception:
        return False


def confirm_zip_aes(pw, p):
    """WinZip AES 强验证：全量 HMAC-SHA1 比对 auth code"""
    try:
        strength = p["strength"]
        klen = p["keybits"]
        key = hashlib.pbkdf2_hmac("sha1", pw.encode("utf-8"), p["salt"], 1000,
                                  2 * klen + 2)
        akey = key[klen:2 * klen]
        salt_len = _AES_SALT_LEN[strength]
        n = p["csize"] - salt_len - 2 - 10
        if n <= 0:
            return False
        with open(p["_path"], "rb") as f:
            f.seek(p["data_off"] + salt_len + 2)
            data = f.read(n)
            auth = f.read(10)
        if len(auth) < 10:
            return False
        return hmac.new(akey, data, hashlib.sha1).digest()[:10] == auth
    except Exception:
        return False

# ===========================================================================
#  第七部分：优先密码清单（高频密码 + 生日）
# ===========================================================================

_TOP_COMMON = [
    "123456", "000000", "111111", "888888", "666666", "520520", "131452",
    "520131", "123123", "112233", "121212", "131313", "141414", "151515",
    "161616", "171717", "181818", "191919", "010101", "020202", "520521",
    "147258", "258369", "741852", "963852", "123321", "654321", "112211",
    "168168", "518518", "102030", "456789", "987654", "111222", "222333",
    "333444", "444555", "555666", "666777", "777888", "888999", "132456",
    "246810", "135790", "314159", "271828", "000001", "000007", "000008",
    "000088", "000123", "000321", "000520", "001001", "005200", "006688",
    "010203", "050505", "060606", "070707", "080808", "090909", "100200",
    "102938", "202020", "303030", "404040", "505050", "606060", "707070",
    "808080", "909090", "123000", "200000", "300000", "500000", "600000",
    "800000", "900000", "100000", "999999", "123789", "520000", "521521",
    "775852", "880088", "990099", "667788", "889988", "998899", "118118",
    "116116", "115115", "113113", "110110", "119119", "117117", "114114",
    "120120", "122122", "996996", "999888", "777777", "222222", "333333",
    "444444", "555555", "135246", "789456", "852963", "456123", "741963",
    "159357", "321654", "987123", "321321", "654654", "987987", "234567",
    "345678", "567890", "678901", "789012", "890123", "901234", "012345",
    "234234", "345345", "456456", "567567", "678678", "789789", "890890",
    "901901", "012012", "990315", "880101", "770202",
]


def build_priority_list(y0=1970, y1=2035):
    """高频密码 + 全部有效生日（YYMMDD / DDMMYY）。已按 set 去重。"""
    import datetime
    plist, seen = [""], {"", }   # 空密码排最前（覆盖“仅权限密码”的 PDF/ZIP）

    def add(s):
        if s not in seen:
            seen.add(s)
            plist.append(s)

    for s in _TOP_COMMON:
        add(s)
    for d in range(10):
        add("%06d" % (d * 111111))
    add("000000")
    day = datetime.date(y0, 1, 1)
    end = datetime.date(y1, 12, 31)
    one = datetime.timedelta(days=1)
    while day <= end:
        yy = "%02d" % (day.year % 100)
        mm = "%02d" % day.month
        dd = "%02d" % day.day
        add(yy + mm + dd)
        add(dd + mm + yy)
        day += one
    return plist


# ===========================================================================
#  第八部分：密码空间（digits / charset / wordlist）与断点进度
# ===========================================================================

CHARSETS = {
    "digits": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "hex": "0123456789abcdef",
}


class Space:
    """统一密码空间：支持 CPU 任务流（字符串列表 / 数字区间）与 GPU 任务流
    （等长批次，16 字节定长缓冲）。gid 为全局顺序序号。"""

    def __init__(self, mode, charset=None, min_len=6, max_len=6,
                 wordlist=None, start=0, end=TOTAL_SPACE):
        self.mode = mode
        self.charset = charset
        self.min_len, self.max_len = min_len, max_len
        self.wordlist = wordlist or []
        self.start, self.end = start, end
        self._layers = None    # charset: [(length, count, base)]
        self._buckets = None   # wordlist: {plen: [lines]}

    # ---- 总量 ----
    def total(self):
        if self.mode == "digits":
            return max(0, self.end - self.start)
        if self.mode == "charset":
            t = 0
            for _, cnt, _ in self._charset_layers():
                t += cnt
            return t
        return len(self.wordlist)

    def _charset_layers(self):
        if self._layers is None:
            c = len(self.charset)
            layers, base = [], 0
            for L in range(self.min_len, self.max_len + 1):
                cnt = c ** L
                layers.append((L, cnt, base))
                base += cnt
            self._layers = layers
        return self._layers

    # ---- gid -> 密码 ----
    def pw_at(self, gid):
        if self.mode == "digits":
            return "%06d" % gid
        if self.mode == "charset":
            for L, cnt, base in self._charset_layers():
                if gid < base + cnt:
                    n, out = gid - base, []
                    cs = self.charset
                    for _ in range(L):
                        out.append(cs[n % len(cs)])
                        n //= len(cs)
                    return "".join(reversed(out))
            return None
        if 0 <= gid < len(self.wordlist):
            return self.wordlist[gid]
        return None

    def describe(self):
        if self.mode == "digits":
            return "6 位纯数字 %06d~%06d" % (self.start, self.end - 1)
        if self.mode == "charset":
            return "字符集[%s] 长度 %d-%d" % (
                (self.charset[:12] + "..") if len(self.charset) > 12 else self.charset,
                self.min_len, self.max_len)
        return "字典 %d 条" % len(self.wordlist)

    # ---- CPU 任务流：yield (gid_start, list_or_range) ----
    def iter_tasks(self, chunk):
        if self.mode == "digits":
            for s in range(self.start, self.end, chunk):
                yield ("D", s, min(s + chunk, self.end))
        elif self.mode == "charset":
            gid = 0
            for L, cnt, base in self._charset_layers():
                for s in range(0, cnt, chunk):
                    n = min(chunk, cnt - s)
                    yield ("L", base + s, [self.pw_at(base + s + i) for i in range(n)])
                gid += cnt
        else:
            for s in range(0, len(self.wordlist), chunk):
                yield ("L", s, self.wordlist[s:s + chunk])

    # ---- GPU 任务流：yield (gid_start, count, pwbuf_bytes_or_None, plen) ----
    def iter_gpu_tasks(self, batch):
        if self.mode == "digits":
            for s in range(self.start, self.end, batch):
                yield (s, min(batch, self.end - s), None, 6)
        elif self.mode == "charset":
            for L, cnt, base in self._charset_layers():
                for s in range(0, cnt, batch):
                    n = min(batch, cnt - s)
                    buf, plen = bytearray(n * 16), 0
                    for i in range(n):
                        b, plen = pack_pw_slot(self.pw_at(base + s + i))
                        buf[i * 16:i * 16 + len(b)] = b
                    yield (base + s, n, bytes(buf), plen)
        else:
            # 字典按长度分桶（GPU 等长批才高效），桶内 gid 连续
            if self._buckets is None:
                buckets = {}
                for line in self.wordlist:
                    b, ln = pack_pw_slot(line)
                    buckets.setdefault(ln, []).append(b)
                self._buckets = sorted(buckets.items())
            for L, blobs in self._buckets:
                for s in range(0, len(blobs), batch):
                    n = min(batch, len(blobs) - s)
                    buf = bytearray(n * 16)
                    for i in range(n):
                        b = blobs[s + i]
                        buf[i * 16:i * 16 + len(b)] = b
                    yield (s, n, bytes(buf), L)
                    # 字典桶的 gid 语义仅用于进度，命中直接回传密码字节


def make_space(args, total_hint=None):
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
                lines = [ln.rstrip("\r\n") for ln in f]
        except OSError as ex:
            raise SystemExit("无法读取字典文件：%r" % (ex,))
        lines = [ln for ln in lines if ln and not ln.startswith("#")]
        if not lines:
            raise SystemExit("字典为空")
        return Space("wordlist", wordlist=lines)
    if args.charset:
        cs = CHARSETS.get(args.charset)
        if cs is None:
            if args.charset.lower() in CHARSETS:
                cs = CHARSETS[args.charset.lower()]
            elif len(args.charset) >= 2:
                cs = args.charset
            else:
                raise SystemExit("--charset 可选 digits/lower/upper/alpha/alnum/hex，或直接传自定义字符集")
        lo = max(1, args.min_len)
        hi = max(lo, args.max_len)
        if len(cs) ** hi > 2 ** 40:
            raise SystemExit("密码空间过大（>2^40），请缩小 charset/长度范围")
        return Space("charset", charset=cs, min_len=lo, max_len=hi)
    return Space("digits", start=args.start, end=args.end)


# ---- 断点进度 ----

def progress_path_for(path):
    return path + ".bcrack.json"


def progress_sig(path, kind, params, space):
    h = hashlib.sha1()
    h.update(kind.encode())
    try:
        h.update(struct.pack("<Q", os.path.getsize(path)))
    except OSError:
        pass
    h.update(repr(sorted(params.items(), key=lambda kv: str(kv[0]))).encode())
    h.update(space.describe().encode())
    return h.hexdigest()[:16]


class Progress:
    """5 秒一存的断点进度。保存 prio_pos（优先清单前缀）+ prio_done + 空间位置 pos。"""

    def __init__(self, path, sig, enabled=True):
        self.file = progress_path_for(path)
        self.sig = sig
        self.enabled = enabled
        self.prio_done = False
        self.prio_pos = 0
        self.pos = 0
        self._last_save = 0.0
        self.loaded = False
        if enabled:
            self._load()

    def _load(self):
        try:
            import json
            with open(self.file, "r", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("v") == 2 and d.get("sig") == self.sig:
                self.prio_done = bool(d.get("prio_done"))
                self.prio_pos = int(d.get("prio_pos", 0))
                self.pos = int(d.get("pos", 0))
                self.loaded = True
        except Exception:
            pass

    def maybe_save(self, force=False):
        now = time.time()
        if not force and now - self._last_save < 5:
            return
        self._last_save = now
        self.save()

    def save(self):
        if not self.enabled:
            return
        try:
            import json
            with open(self.file, "w", encoding="utf-8") as f:
                json.dump({"v": 2, "sig": self.sig, "prio_done": self.prio_done,
                           "prio_pos": self.prio_pos, "pos": self.pos,
                           "time": time.time()}, f)
        except Exception:
            pass

    def clear(self):
        try:
            os.remove(self.file)
        except OSError:
            pass


# ===========================================================================
#  第九部分：CPU 多进程 worker（支持全部加密种类）
# ===========================================================================

_W = {}   # worker 全局状态


def _worker_init(cfg):
    global _W
    kind = cfg["kind"]
    spin = cfg.get("spin", 0)
    _W = {"kind": kind, "spin": spin}
    if kind == "agile":
        _W.update({
            "salt": cfg["salt"], "spin": spin, "hasher": HASHERS[cfg["alg"]],
            "keylen": cfg["keyBits"] // 8,
            "evi": cfg["encVerifierInput"], "evh": cfg["encVerifierHash"],
            "prefix": [struct.pack("<I", i) for i in range(spin)],
            "fast": cfg.get("use_crypto_aes", False),
        })
        if _W["fast"]:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            _W["Cipher"], _W["algorithms"], _W["modes"] = Cipher, algorithms, modes

        def _blk(ct, key, iv):
            if _W["fast"]:
                c = _W["Cipher"](_W["algorithms"].AES(key), _W["modes"].CBC(iv))
                d = c.decryptor()
                return (d.update(bytes(ct[:16])) + d.finalize())[:16]
            return aes_cbc_decrypt_first_block(ct, key, iv)

        _W["blk"] = _blk
    elif kind == "std":
        _W.update({
            "salt": cfg["salt"], "spin": spin,
            "prefix": [struct.pack("<I", i) for i in range(spin)],
            "keylen": cfg["keySize"] // 8, "ev": cfg["encVerifier"],
            "evh": cfg["encVerifierHash"], "rc4": cfg["cipher"] == "RC4",
        })
    else:
        _W["params"] = cfg["params"]
        _W["vfn"] = {
            "xor": verify_xor_doc,
            "pdf_r2": verify_pdf_rc4,
            "pdf_r3": verify_pdf_rc4,
            "pdf_r4_aes": verify_pdf_aesv2,
            "pdf_r6": verify_pdf_r6,
            "zip_crypto": verify_zip_crypto,
            "zip_aes": verify_zip_aes,
        }[kind]
        # ZIP 弱校验位（1/65536）需完整解密二次确认，拦截大空间扫描的假阳性
        _W["confirm"] = {
            "zip_crypto": confirm_zip_crypto,
            "zip_aes": confirm_zip_aes,
        }.get(kind)


def _worker_check(task):
    """task = (tag, gid, payload)；返回 (tag, gid, tried, 命中密码或 None)"""
    tkind, _gid, payload = task
    W = _W
    if tkind == "D":
        s, e = payload
        cands = ("%06d" % n for n in range(s, e))
        n_tried = e - s
    else:
        cands = payload
        n_tried = len(payload)

    kind = W["kind"]
    if kind == "agile":
        salt, hasher, prefix = W["salt"], W["hasher"], W["prefix"]
        keylen, evi, evh, blk = W["keylen"], W["evi"], W["evh"], W["blk"]
        for pw in cands:
            h = hasher(salt + pw.encode("utf-16-le")).digest()
            for p in prefix:
                x = hasher(p)
                x.update(h)
                h = x.digest()
            k1 = hasher(h + BLK_VERIFIER).digest()[:keylen]
            if hasher(blk(evi, k1, salt)).digest()[:16] == blk(
                    evh, hasher(h + BLK_VERIFIER_HASH).digest()[:keylen], salt):
                return (tkind, _gid, n_tried, pw)
        return (tkind, _gid, n_tried, None)

    if kind == "std":
        salt, hasher, prefix = W["salt"], hashlib.sha1, W["prefix"]
        keylen, ev, evh, rc4 = W["keylen"], W["ev"], W["evh"], W["rc4"]
        b36, b5c = B36, B5C
        for pw in cands:
            h = hasher(salt + pw.encode("utf-16-le")).digest()
            for p in prefix:
                x = hasher(p)
                x.update(h)
                h = x.digest()
            hf = hasher(h + b"\x00\x00\x00\x00").digest()
            b1 = bytearray(b36)
            b1[:20] = bytes(a ^ b for a, b in zip(hf, b36[:20]))
            b2 = bytearray(b5c)
            b2[:20] = bytes(a ^ b for a, b in zip(hf, b5c[:20]))
            key = (hasher(bytes(b1)).digest() + hasher(bytes(b2)).digest())[:keylen]
            if rc4:
                verifier = rc4_crypt(key, ev)
                if hasher(verifier).digest() == rc4_crypt(key, evh)[:20]:
                    return (tkind, _gid, n_tried, pw)
            else:
                verifier = aes_ecb_decrypt(ev, key)
                if hasher(verifier).digest() == fast_ecb_decrypt(evh, key)[:20]:
                    return (tkind, _gid, n_tried, pw)
        return (tkind, _gid, n_tried, None)

    # 其余种类（xor / pdf / zip）
    vfn, params = W["vfn"], W["params"]
    confirm = W.get("confirm")
    for pw in cands:
        if vfn(pw, params):
            # 弱校验位通过 -> 完整解密确认（假阳性则继续扫）
            if confirm is None or confirm(pw, params):
                return (tkind, _gid, n_tried, pw)
    return (tkind, _gid, n_tried, None)

# ===========================================================================
#  第十部分：GPU 加速内核 (CUDA / CuPy)
#   - SHA-1/256/384/512 × AES-128/192/256 全组合（12 个入口）
#   - cubin 磁盘缓存（按 源码+架构 hash，重跑免编译）
#   - 多 GPU 分片并行；-arch 按 compute capability 显式指定
#   - 启动前校验加密参数，不支持的组合明确回退 CPU（不再静默算错）
# ===========================================================================

_CUDA_SRC = r'''
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define H_SHA1   0
#define H_SHA256 1
#define H_SHA384 2
#define H_SHA512 3

__constant__ u64 K512[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

__constant__ u32 K256[64] = {
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

__constant__ u8 SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

__constant__ u8 RSBOX[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

__constant__ u8 RCON[15] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a};

__constant__ u8 BLK_V[8]  = {0xFE,0xA7,0xD2,0x76,0x3B,0x4B,0x9E,0x79};
__constant__ u8 BLK_VH[8] = {0xD7,0xAA,0x0F,0x6D,0x30,0x61,0x34,0x4E};

__device__ __forceinline__ u64 rotr(u64 x, int n) { return (x >> n) | (x << (64 - n)); }
__device__ __forceinline__ u32 rotr32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

// ---------------- SHA-512 家族压缩函数（384 仅 IV 与截断不同） ----------------
__device__ __forceinline__ void sha512_block(u64 *st, u64 *w) {
    u64 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        u64 wi;
        if (i < 16) { wi = w[i]; }
        else {
            u64 x1 = w[(i+1)&15], x2 = w[(i+14)&15];
            u64 x3 = w[i&15],     x4 = w[(i+9)&15];
            wi = x3 + (rotr(x1,1)^rotr(x1,8)^(x1>>7)) + x4 + (rotr(x2,19)^rotr(x2,61)^(x2>>6));
            w[i&15] = wi;
        }
        u64 t1 = h + (rotr(e,14)^rotr(e,18)^rotr(e,41)) + ((e&f)^((~e)&g)) + K512[i] + wi;
        u64 t2 = (rotr(a,28)^rotr(a,34)^rotr(a,39)) + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

// ---------------- SHA-256 压缩函数 ----------------
__device__ __forceinline__ void sha256_block(u32 *st, u32 *w) {
    u32 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        u32 wi;
        if (i < 16) { wi = w[i]; }
        else {
            u32 x1 = w[(i+1)&15], x2 = w[(i+14)&15];
            u32 s0 = rotr32(x1,7) ^ rotr32(x1,18) ^ (x1>>3);
            u32 s1 = rotr32(x2,17) ^ rotr32(x2,19) ^ (x2>>10);
            wi = w[i&15] + s0 + w[(i+9)&15] + s1;
            w[i&15] = wi;
        }
        u32 S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        u32 ch = (e&f) ^ ((~e)&g);
        u32 t1 = h + S1 + ch + K256[i] + wi;
        u32 S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        u32 mj = (a&b) ^ (a&c) ^ (b&c);
        u32 t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

// ---------------- SHA-1 压缩函数 ----------------
__device__ __forceinline__ void sha1_block(u32 *st, u32 *w) {
    u32 a=st[0],b=st[1],c=st[2],d=st[3],e=st[4];
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        u32 wi;
        if (i < 16) { wi = w[i]; }
        else {
            // SHA-1 扩展: w[i-3]^w[i-8]^w[i-14]^w[i-16]，mod16 即 (i+13)/(i+8)/(i+2)/(i)
            u32 x = w[(i+13)&15] ^ w[(i+8)&15] ^ w[(i+2)&15] ^ w[i&15];
            wi = (x<<1) | (x>>31);
            w[i&15] = wi;
        }
        u32 f, k;
        if (i < 20)      { f = (b&c) | ((~b)&d);      k = 0x5A827999u; }
        else if (i < 40){ f = b ^ c ^ d;             k = 0x6ED9EBA1u; }
        else if (i < 60){ f = (b&c) | (b&d) | (c&d); k = 0x8F1BBCDCu; }
        else            { f = b ^ c ^ d;             k = 0xCA62C1D6u; }
        u32 t = ((a<<5)|(a>>27)) + f + e + k + wi;
        e=d; d=c; c=(b<<30)|(b>>2); b=a; a=t;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e;
}

// ---------------- 通用单块哈希（消息 <= 55/111 字节） ----------------
template<int HASHID>
__device__ __forceinline__ int hlen() {
    if (HASHID == H_SHA1)   return 20;
    if (HASHID == H_SHA256) return 32;
    if (HASHID == H_SHA384) return 48;
    return 64;
}

template<int HASHID>
__device__ __forceinline__ void hash_msg(const u8* data, int len, u8* out) {
    if (HASHID == H_SHA1 || HASHID == H_SHA256) {
        u32 w[16];
        #pragma unroll
        for (int i=0;i<16;i++) w[i]=0;
        #pragma unroll 4
        for (int i=0;i<len;i++) w[i>>2] |= ((u32)data[i]) << (24 - (i&3)*8);
        w[len>>2] |= 0x80u << (24 - (len&3)*8);
        w[15] = (u32)len * 8;
        if (HASHID == H_SHA1) {
            u32 st[5] = {0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
            sha1_block(st, w);
            #pragma unroll
            for (int i=0;i<5;i++){ u32 v=st[i];
                #pragma unroll
                for(int k=0;k<4;k++) out[i*4+k]=(u8)(v>>(24-k*8)); }
        } else {
            u32 st[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                         0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
            sha256_block(st, w);
            #pragma unroll
            for (int i=0;i<8;i++){ u32 v=st[i];
                #pragma unroll
                for(int k=0;k<4;k++) out[i*4+k]=(u8)(v>>(24-k*8)); }
        }
    } else {
        u64 w[16];
        #pragma unroll
        for (int i=0;i<16;i++) w[i]=0;
        #pragma unroll 4
        for (int i=0;i<len;i++) w[i>>3] |= ((u64)data[i]) << (56 - (i&7)*8);
        w[len>>3] |= 0x80ULL << (56 - (len&7)*8);
        w[15] = (u64)len * 8;
        if (HASHID == H_SHA384) {
            u64 st[8] = {0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,
                         0x152fecd8f70e5939ULL,0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,
                         0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};
            sha512_block(st, w);
            #pragma unroll
            for (int i=0;i<6;i++){ u64 v=st[i];
                #pragma unroll
                for(int k=0;k<8;k++) out[i*8+k]=(u8)(v>>(56-k*8)); }
        } else {
            u64 st[8] = {0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,
                         0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
            sha512_block(st, w);
            #pragma unroll
            for (int i=0;i<8;i++){ u64 v=st[i];
                #pragma unroll
                for(int k=0;k<8;k++) out[i*8+k]=(u8)(v>>(56-k*8)); }
        }
    }
}

// ---------------- Agile KDF 迭代步（各 hash 特化：H = HASH(u32le(i) || H)） ----------------
__device__ __forceinline__ void iter_s1(u32 *H, u32 i) {
    u32 b = ((i & 0xFFu) << 24) | ((i & 0xFF00u) << 8) | ((i >> 8) & 0xFF00u) | ((i >> 24) & 0xFFu);
    u32 w[16];
    w[0]=b; w[1]=H[0]; w[2]=H[1]; w[3]=H[2]; w[4]=H[3]; w[5]=H[4];
    w[6]=0x80000000u;
    #pragma unroll
    for (int j=7;j<15;j++) w[j]=0;
    w[15]=192;
    u32 st[5] = {0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    sha1_block(st, w);
    #pragma unroll
    for (int j=0;j<5;j++) H[j] = st[j];
}

__device__ __forceinline__ void iter_s256(u32 *H, u32 i) {
    u32 b = ((i & 0xFFu) << 24) | ((i & 0xFF00u) << 8) | ((i >> 8) & 0xFF00u) | ((i >> 24) & 0xFFu);
    u32 w[16];
    w[0]=b; w[1]=H[0]; w[2]=H[1]; w[3]=H[2]; w[4]=H[3];
    w[5]=H[4]; w[6]=H[5]; w[7]=H[6]; w[8]=H[7];
    w[9]=0x80000000u;
    #pragma unroll
    for (int j=10;j<15;j++) w[j]=0;
    w[15]=288;
    u32 st[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                 0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    sha256_block(st, w);
    #pragma unroll
    for (int j=0;j<8;j++) H[j] = st[j];
}

// SHA-384 与 SHA-512 共用 u64 路径，仅消息长度 / IV / 输出长度不同
template<int IS384>
__device__ __forceinline__ void iter_s512f(u64 *H, u32 i) {
    u32 b = ((i & 0xFFu) << 24) | ((i & 0xFF00u) << 8) | ((i >> 8) & 0xFF00u) | ((i >> 24) & 0xFFu);
    u64 w[16];
    #pragma unroll
    for (int j=0;j<16;j++) w[j]=0;
    w[0] = (((u64)b) << 32) | (H[0] >> 32);
    w[1] = (H[0] << 32) | (H[1] >> 32);
    w[2] = (H[1] << 32) | (H[2] >> 32);
    w[3] = (H[2] << 32) | (H[3] >> 32);
    w[4] = (H[3] << 32) | (H[4] >> 32);
    w[5] = (H[4] << 32) | (H[5] >> 32);
    if (IS384) {
        w[6] = (H[5] << 32) | 0x80000000ULL;   // 52 字节消息 + 0x80
        w[15] = 416;
    } else {
        w[6] = (H[5] << 32) | (H[6] >> 32);
        w[7] = (H[6] << 32) | (H[7] >> 32);
        w[8] = (H[7] << 32) | 0x80000000ULL;   // 68 字节消息 + 0x80
        w[15] = 544;
    }
    u64 st[8];
    if (IS384) {
        st[0]=0xcbbb9d5dc1059ed8ULL; st[1]=0x629a292a367cd507ULL;
        st[2]=0x9159015a3070dd17ULL; st[3]=0x152fecd8f70e5939ULL;
        st[4]=0x67332667ffc00b31ULL; st[5]=0x8eb44a8768581511ULL;
        st[6]=0xdb0c2e0d64f98fa7ULL; st[7]=0x47b5481dbefa4fa4ULL;
    } else {
        st[0]=0x6a09e667f3bcc908ULL; st[1]=0xbb67ae8584caa73bULL;
        st[2]=0x3c6ef372fe94f82bULL; st[3]=0xa54ff53a5f1d36f1ULL;
        st[4]=0x510e527fade682d1ULL; st[5]=0x9b05688c2b3e6c1fULL;
        st[6]=0x1f83d9abfb41bd6bULL; st[7]=0x5be0cd19137e2179ULL;
    }
    sha512_block(st, w);
    if (IS384) {
        #pragma unroll
        for (int j=0;j<6;j++) H[j] = st[j];
    } else {
        #pragma unroll
        for (int j=0;j<8;j++) H[j] = st[j];
    }
}

// ---------------- AES 密钥扩展（128/192/256 泛化）与 CBC 首块解密 ----------------
__device__ __forceinline__ u8 mul2(u8 a){ return (u8)((a<<1) ^ ((a>>7)*0x1B)); }

template<int KEYBYTES>
__device__ void aes_expand(const u8* key, u8* rk) {
    const int nk = KEYBYTES/4;
    const int words = 4*(nk+7);
    #pragma unroll
    for (int i=0;i<KEYBYTES;i++) rk[i]=key[i];
    u8 t[4];
    for (int i=nk;i<words;i++) {
        t[0]=rk[(i-1)*4+0]; t[1]=rk[(i-1)*4+1]; t[2]=rk[(i-1)*4+2]; t[3]=rk[(i-1)*4+3];
        if (i % nk == 0) {
            u8 tmp=t[0];
            t[0]=(u8)(SBOX[t[1]]^RCON[i/nk-1]); t[1]=SBOX[t[2]]; t[2]=SBOX[t[3]]; t[3]=SBOX[tmp];
        } else if (nk > 6 && i % nk == 4) {
            t[0]=SBOX[t[0]]; t[1]=SBOX[t[1]]; t[2]=SBOX[t[2]]; t[3]=SBOX[t[3]];
        }
        #pragma unroll
        for (int j=0;j<4;j++) rk[i*4+j] = (u8)(rk[(i-nk)*4+j] ^ t[j]);
    }
}

template<int KEYBYTES>
__device__ void aes_cbc_first(const u8* in, const u8* key, const u8* iv, u8* out) {
    const int nr = KEYBYTES/4 + 6;
    u8 rk[16*15];
    aes_expand<KEYBYTES>(key, rk);
    u8 s[16], t[16];
    #pragma unroll
    for (int i=0;i<16;i++) s[i] = (u8)(in[i] ^ rk[nr*16+i]);
    for (int rnd=nr-1; rnd>0; rnd--) {
        #pragma unroll
        for (int c=0;c<4;c++)
            #pragma unroll
            for (int r=0;r<4;r++) t[4*c+r] = RSBOX[s[4*((c-r)&3)+r]];
        #pragma unroll
        for (int i=0;i<16;i++) t[i] ^= rk[rnd*16+i];
        #pragma unroll
        for (int c=0;c<4;c++) {
            u8 a0=t[4*c],a1=t[4*c+1],a2=t[4*c+2],a3=t[4*c+3];
            u8 a0_2=mul2(a0),a0_4=mul2(a0_2),a0_8=mul2(a0_4);
            u8 a1_2=mul2(a1),a1_4=mul2(a1_2),a1_8=mul2(a1_4);
            u8 a2_2=mul2(a2),a2_4=mul2(a2_2),a2_8=mul2(a2_4);
            u8 a3_2=mul2(a3),a3_4=mul2(a3_2),a3_8=mul2(a3_4);
            s[4*c+0]=(u8)(a0_8^a0_4^a0_2 ^ a1_8^a1_2^a1 ^ a2_8^a2_4^a2 ^ a3_8^a3);
            s[4*c+1]=(u8)(a0_8^a0 ^ a1_8^a1_4^a1_2 ^ a2_8^a2_2^a2 ^ a3_8^a3_4^a3);
            s[4*c+2]=(u8)(a0_8^a0_4^a0 ^ a1_8^a1 ^ a2_8^a2_4^a2_2 ^ a3_8^a3_2^a3);
            s[4*c+3]=(u8)(a0_8^a0_2^a0 ^ a1_8^a1_4^a1 ^ a2_8^a2 ^ a3_8^a3_4^a3_2);
        }
    }
    #pragma unroll
    for (int c=0;c<4;c++)
        #pragma unroll
        for (int r=0;r<4;r++) out[4*c+r] = (u8)(RSBOX[s[4*((c-r)&3)+r]] ^ rk[4*c+r] ^ iv[4*c+r]);
}

// ---------------- 主流程模板：HASHID × KEYBYTES ----------------
template<int HASHID, int KEYBYTES>
__device__ void crack_impl(
    const u8* __restrict__ salt, const u8* __restrict__ evi, const u8* __restrict__ evh,
    int spin, long long base, int count,
    const u8* __restrict__ pwbuf, int plen, int use_buf,
    int* __restrict__ found, u8* __restrict__ found_pw)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    u8 pwb[16];
    // 注意：必须按 use_buf 分支，不能按 pwbuf 是否为空指针判断——
    // 主机端 digits 模式传的是 1 字节 dummy（非 NULL），按指针判断会永远走缓冲分支。
    if (use_buf) {
        #pragma unroll
        for (int k=0;k<16;k++) pwb[k] = pwbuf[(long)idx * 16 + k];
    } else {
        int n = (int)(base + idx);
        pwb[0]=(u8)(n/100000 + '0'); n%=100000;
        pwb[1]=(u8)(n/10000 + '0');  n%=10000;
        pwb[2]=(u8)(n/1000 + '0');   n%=1000;
        pwb[3]=(u8)(n/100 + '0');    n%=100;
        pwb[4]=(u8)(n/10 + '0');
        pwb[5]=(u8)(n%10 + '0');
        plen = 6;
    }

    // ---- 1) H = HASH(salt || pw_utf16le) ----
    u8 h0in[46];
    #pragma unroll
    for (int i=0;i<16;i++) h0in[i]=salt[i];
    #pragma unroll 8
    for (int i=0;i<plen;i++) { h0in[16+i*2] = pwb[i]; h0in[17+i*2] = 0; }
    int m0 = 16 + plen*2;

    u8 H[64];
    hash_msg<HASHID>(h0in, m0, H);

    // ---- 2) 迭代链 ----
    if (HASHID == H_SHA1) {
        u32 h[5];
        #pragma unroll
        for (int i=0;i<5;i++) h[i] = ((u32)H[i*4]<<24)|((u32)H[i*4+1]<<16)|((u32)H[i*4+2]<<8)|((u32)H[i*4+3]);
        for (int i = 0; i < spin; i++) iter_s1(h, (u32)i);
        #pragma unroll
        for (int i=0;i<5;i++){ u32 v=h[i];
            #pragma unroll
            for(int k=0;k<4;k++) H[i*4+k]=(u8)(v>>(24-k*8)); }
    } else if (HASHID == H_SHA256) {
        u32 h[8];
        #pragma unroll
        for (int i=0;i<8;i++) h[i] = ((u32)H[i*4]<<24)|((u32)H[i*4+1]<<16)|((u32)H[i*4+2]<<8)|((u32)H[i*4+3]);
        for (int i = 0; i < spin; i++) iter_s256(h, (u32)i);
        #pragma unroll
        for (int i=0;i<8;i++){ u32 v=h[i];
            #pragma unroll
            for(int k=0;k<4;k++) H[i*4+k]=(u8)(v>>(24-k*8)); }
    } else {
        u64 h[8];
        #pragma unroll
        for (int i=0;i<8;i++){ u64 v=0;
            #pragma unroll
            for(int k=0;k<8;k++) v = (v<<8) | H[i*8+k];
            h[i]=v; }
        if (HASHID == H_SHA384) {
            for (int i = 0; i < spin; i++) iter_s512f<1>(h, (u32)i);
            #pragma unroll
            for (int i=0;i<6;i++){ u64 v=h[i];
                #pragma unroll
                for(int k=0;k<8;k++) H[i*8+k]=(u8)(v>>(56-k*8)); }
        } else {
            for (int i = 0; i < spin; i++) iter_s512f<0>(h, (u32)i);
            #pragma unroll
            for (int i=0;i<8;i++){ u64 v=h[i];
                #pragma unroll
                for(int k=0;k<8;k++) H[i*8+k]=(u8)(v>>(56-k*8)); }
        }
    }

    // ---- 3) k1 = HASH(H || BLK_V)[:KEYBYTES]，k2 同理 ----
    const int hl = hlen<HASHID>();
    u8 tmp[72], hout[64], k1[32], k2[32];
    #pragma unroll 8
    for (int i=0;i<hl;i++) tmp[i]=H[i];
    #pragma unroll
    for (int i=0;i<8;i++) tmp[hl+i]=BLK_V[i];
    hash_msg<HASHID>(tmp, hl+8, hout);
    #pragma unroll
    for (int i=0;i<KEYBYTES;i++) k1[i]=hout[i];
    #pragma unroll 8
    for (int i=0;i<hl;i++) tmp[i]=H[i];
    #pragma unroll
    for (int i=0;i<8;i++) tmp[hl+i]=BLK_VH[i];
    hash_msg<HASHID>(tmp, hl+8, hout);
    #pragma unroll
    for (int i=0;i<KEYBYTES;i++) k2[i]=hout[i];

    // ---- 4) 校验 ----
    u8 vin[16], actual[64], expect[16];
    aes_cbc_first<KEYBYTES>(evi, k1, salt, vin);
    hash_msg<HASHID>(vin, 16, actual);
    aes_cbc_first<KEYBYTES>(evh, k2, salt, expect);
    bool ok = true;
    #pragma unroll
    for (int i=0;i<16;i++) if (actual[i] != expect[i]) ok = false;
    if (ok) {
        int old = atomicCAS(found, -1, use_buf ? idx : (int)(base + idx));
        if (old == -1 && found_pw) {
            #pragma unroll
            for (int k=0;k<16;k++) found_pw[k] = pwb[k];
        }
    }
}

#define DEF_KERNEL(name, hid, kb) \
extern "C" __global__ void name( \
    const u8* __restrict__ salt, const u8* __restrict__ evi, const u8* __restrict__ evh, \
    int spin, long long base, int count, const u8* __restrict__ pwbuf, int plen, \
    int use_buf, int* __restrict__ found, u8* __restrict__ found_pw) \
{ crack_impl<hid, kb>(salt, evi, evh, spin, base, count, pwbuf, plen, use_buf, found, found_pw); }

DEF_KERNEL(crack_h1_k128,   0, 16)
DEF_KERNEL(crack_h1_k192,   0, 24)
DEF_KERNEL(crack_h1_k256,   0, 32)
DEF_KERNEL(crack_h256_k128, 1, 16)
DEF_KERNEL(crack_h256_k192, 1, 24)
DEF_KERNEL(crack_h256_k256, 1, 32)
DEF_KERNEL(crack_h384_k128, 2, 16)
DEF_KERNEL(crack_h384_k192, 2, 24)
DEF_KERNEL(crack_h384_k256, 2, 32)
DEF_KERNEL(crack_h512_k128, 3, 16)
DEF_KERNEL(crack_h512_k192, 3, 24)
DEF_KERNEL(crack_h512_k256, 3, 32)
'''

# ---------------------------------------------------------------------------
#  GPU Python 管理层
# ---------------------------------------------------------------------------

GPU_KERNELS = {}
for _h, _tag in (("SHA1", "1"), ("SHA256", "256"), ("SHA384", "384"), ("SHA512", "512")):
    for _k in (128, 192, 256):
        GPU_KERNELS[(_h, _k)] = "crack_h%s_k%d" % (_tag, _k)

_GPU_STATE = {"modules": None, "devices": [], "err": None, "desc": ""}


def gpu_check_support(kind, params):
    """GPU 启动前的加密参数校验。
    v1.1 的致命缺陷：内核只支持 SHA512+AES256 却来者不拒，遇到其它参数组合
    会静默算错（表现为扫完找不到密码）。v1.2 起不支持的组合明确回退 CPU。"""
    if kind != "agile":
        return False, "GPU 内核仅支持 Agile 加密（当前：%s），已回退 CPU" % kind
    if params.get("cipher", "AES") != "AES":
        return False, "该文件用 %s 加密（非 AES），GPU 内核不支持，已回退 CPU" % params["cipher"]
    if params.get("alg") not in HASHERS:
        return False, "哈希算法 %s 不在支持列表，已回退 CPU" % params.get("alg")
    if params.get("alg") == "SHA1" and params.get("keyBits", 128) > 160:
        return False, ("SHA1 摘要仅 20 字节，派生不出 %d 位 AES 密钥，"
                       "已回退 CPU" % params.get("keyBits"))
    if params.get("keyBits") not in (128, 192, 256):
        return False, "密钥长度 %s 不支持，已回退 CPU" % params.get("keyBits")
    if params.get("blockSize", 16) != 16:
        return False, "blockSize != 16，已回退 CPU"
    return True, None


def _import_cupy_diag():
    """导入 cupy 并保留失败原因（区分"未安装"与"DLL 被系统策略拦截"）"""
    try:
        import cupy  # noqa
        return True, None
    except Exception as ex:
        return False, str(ex)


def gpu_probe(mirror=None, auto_install=None):
    """探测 GPU：cupy -> nvidia-smi 诊断 -> 可选自动安装。
    返回 (可用?, 描述)。失败原因分三类：无 N 卡 / 驱动过旧 / 缺依赖。"""
    if _GPU_STATE["err"]:
        return False, _GPU_STATE["err"]
    cp_ok, cp_err = _import_cupy_diag()
    if cp_ok:
        try:
            import cupy as cp
            n = cp.cuda.runtime.getDeviceCount()
            if n >= 1:
                descs = []
                for i in range(n):
                    prop = cp.cuda.runtime.getDeviceProperties(i)
                    name = prop["name"]
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", "replace")
                    descs.append("%s(sm_%d%d)" % (name, int(prop.get("major", 0) or 0),
                                                  int(prop.get("minor", 0) or 0)))
                _GPU_STATE["desc"] = " + ".join(descs)
                return True, _GPU_STATE["desc"]
        except Exception as ex:
            # cupy 装了但驱动/运行时不匹配
            return False, "cupy 已安装但无法初始化 CUDA：%s" % _strip_ex(ex)
    else:
        # cupy 导入失败：先识别 Windows 应用程序控制策略（Smart App Control/WDAC）
        # 拦截 DLL 的情况——此时重装 cupy 完全无用，必须换解释器或改安全策略
        low = (cp_err or "").lower()
        if ("应用程序控制" in (cp_err or "") or "application control" in low
                or "智能应用控制" in (cp_err or "")):
            _GPU_STATE["err"] = (
                "cupy 已安装，但其 DLL 被 Windows 应用程序控制策略"
                "（智能应用控制/WDAC）拦截，重装无效。解决办法（任选一）：\n"
                "    1) 改用装有可用 cupy 的解释器运行本脚本（如：py -3.13 脚本路径）\n"
                "    2) Windows 安全中心 -> 应用和浏览器控制 -> 智能应用控制 设置为关闭")
            return False, _GPU_STATE["err"]
    # 没有 cupy：分类诊断
    gpus, smi_err = nvidia_smi_probe()
    if not gpus:
        reason = smi_err or "未检测到 NVIDIA 显卡"
        _GPU_STATE["err"] = reason + " -> 仅 CPU 模式（无需安装任何 GPU 依赖）"
        return False, _GPU_STATE["err"]
    # 有 N 卡但没装 cupy
    names = "、".join(g[0] for g in gpus)
    cuda_major = cuda_from_driver(gpus[0][1])
    if cuda_major < 11:
        _GPU_STATE["err"] = ("显卡 %s 的驱动（%s）过旧，无法支持任何 CUDA 版本的 cupy；"
                             "请先升级 NVIDIA 驱动" % (names, gpus[0][1]))
        return False, _GPU_STATE["err"]
    pkg, pinned = cupy_package_for(cuda_major)
    why = ("检测到 NVIDIA 显卡 %s（驱动 %s，支持到 CUDA %d），"
           "安装 %s 后可启用 GPU 加速（约快 60 倍）"
           % (names, gpus[0][1], cuda_major, pkg))
    pkgs = [pinned] if pinned else [pkg]
    if cuda_major >= 12:
        pkgs += ["nvidia-cuda-nvrtc"]
    ok = maybe_install("cupy", pkgs, why, mirror, auto_install)
    if ok and try_import("cupy"):
        try:
            import cupy as cp
            if cp.cuda.runtime.getDeviceCount() >= 1:
                prop = cp.cuda.runtime.getDeviceProperties(0)
                name = prop["name"]
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                _GPU_STATE["desc"] = "%s (sm_%d%d)" % (
                    name, int(prop.get("major", 0) or 0), int(prop.get("minor", 0) or 0))
                return True, _GPU_STATE["desc"]
        except Exception as ex:
            _GPU_STATE["err"] = "cupy 安装后仍无法初始化：%s" % _strip_ex(ex)
            return False, _GPU_STATE["err"]
    _GPU_STATE["err"] = "cupy 未安装，使用 CPU 模式"
    return False, _GPU_STATE["err"]


def _strip_ex(ex):
    s = str(ex)
    return s if len(s) < 300 else s[:300] + "..."


def _kernel_cache_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "docxcrack_kernels")
    else:
        d = os.path.join(os.path.expanduser("~"), ".cache", "docxcrack_kernels")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.join(os.environ.get("TEMP", "/tmp"), "docxcrack_kernels")
        os.makedirs(d, exist_ok=True)
    return d


def _translate_nvrtc_error(ex):
    s = str(ex).lower()
    if "sm_120" in s or "compute_120" in s or "unsupported" in s and ("arch" in s or "gpu" in s):
        return ("你的 NVRTC 版本无法为当前显卡架构编译内核。\n"
                "  RTX 50 系（Blackwell）需要 CUDA 12.8+ 的 NVRTC：\n"
                "    1) 升级 NVIDIA 驱动到 570 或更新\n"
                "    2) pip install -U cupy-cuda12x nvidia-cuda-nvrtc")
    if "nvrtc" in s and ("not found" in s or "load" in s):
        return ("NVRTC 库加载失败，尝试：pip install nvidia-cuda-nvrtc\n"
                "  或升级 NVIDIA 驱动后重装 cupy")
    return None


def gpu_compile(verbose=True):
    """编译（或从磁盘缓存加载）全部 12 个内核入口。多 GPU 时逐设备加载。
    返回 {kernel_name: fn}（单卡）；多卡时返回 [ {..}, {..} ] 列表。"""
    if _GPU_STATE["modules"] is not None:
        return _GPU_STATE["modules"]
    import cupy as cp
    n_dev = cp.cuda.runtime.getDeviceCount()
    mods = []
    for dev in range(n_dev):
        with cp.cuda.Device(dev):
            prop = cp.cuda.runtime.getDeviceProperties(dev)
            maj = int(prop.get("major", 0) or 0)
            minr = int(prop.get("minor", 0) or 0)
            arch = "sm_%d%d" % (maj, minr)
            tag = hashlib.sha1(
                (_CUDA_SRC + "|" + arch + "|" + VERSION).encode()).hexdigest()[:16]
            cache = os.path.join(_kernel_cache_dir(), "kernel_%s_%s.cubin" % (arch, tag))
            mod = None
            # 缓存文件必须非空（历史上曾因接口不兼容写入过 0 字节文件，
            # 且 CuPy 模块加载是惰性的，坏文件要到 get_function 才炸）
            if os.path.isfile(cache) and os.path.getsize(cache) > 0:
                try:
                    mod = cp.RawModule(path=cache)
                except Exception:
                    mod = None
            if mod is not None:
                if verbose:
                    print("  GPU#%d 内核：命中磁盘缓存（%s，秒加载）" % (dev, arch))
            else:
                if verbose:
                    print("  GPU#%d 正在编译内核（%s，首次约 1 分钟，之后走缓存）..." % (dev, arch))
                t0 = time.time()
                try:
                    from cupy.cuda import compiler
                    cubin = None
                    # 兼容不同 CuPy 版本的 NVRTC 接口：
                    #   cupy>=13: compile_using_nvrtc(source, options, arch)
                    #       arch 13 用 'sm_120'；14 起要裸数字 '120'
                    #       13 返回 bytes；14 起返回 (bytes, name_map) 元组
                    #   旧版:     compile(source, options=(-arch=...))
                    try:
                        if hasattr(compiler, "compile_using_nvrtc"):
                            try:
                                res = compiler.compile_using_nvrtc(
                                    _CUDA_SRC, options=("-std=c++17",), arch=arch)
                            except (ValueError, TypeError):
                                # CuPy 14 起 arch 参数要传裸数字（'120'），
                                # CuPy 13 才接受 'sm_120' 格式
                                res = compiler.compile_using_nvrtc(
                                    _CUDA_SRC, options=("-std=c++17",),
                                    arch=arch.replace("sm_", ""))
                            cubin = res[0] if isinstance(res, tuple) else res
                        else:
                            cubin = compiler.compile(
                                _CUDA_SRC, options=("-std=c++17", "-arch=%s" % arch))
                    except Exception:
                        # 兜底：直接驱动 NVRTC（不触碰 CUDA runtime 初始化）
                        prog = compiler._NVRTCProgram(_CUDA_SRC, "kern.cu")
                        res = prog.compile(
                            ("-std=c++17",
                             "-arch=%s" % arch.replace("sm_", "compute_"),
                             "--device-as-default-execution-space"))
                        cubin = res[0] if isinstance(res, tuple) else res
                    if not cubin:
                        raise RuntimeError("NVRTC 返回空产物")
                    # 先写临时文件再原子替换，避免留下 0 字节/半截缓存
                    tmp = cache + ".tmp"
                    with open(tmp, "wb") as f:
                        f.write(cubin)
                    os.replace(tmp, cache)
                    mod = cp.RawModule(path=cache)
                except Exception as ex:
                    hint = _translate_nvrtc_error(ex)
                    if hint:
                        raise RuntimeError(hint) from None
                    # 二级兜底：让 CuPy 自己编译（无磁盘缓存）
                    try:
                        mod = cp.RawModule(code=_CUDA_SRC,
                                           options=("-std=c++17", "-arch=%s" % arch,))
                    except Exception as ex2:
                        hint2 = _translate_nvrtc_error(ex2)
                        raise RuntimeError(hint2 or ("内核编译失败：%s" % _strip_ex(ex2))) from None
                if verbose:
                    print("  GPU#%d 编译完成（%.0f 秒）" % (dev, time.time() - t0))
        mods.append(mod)
    _GPU_STATE["modules"] = mods
    _GPU_STATE["devices"] = list(range(n_dev))
    return mods


def gpu_scan(params, prio, space, progress, on_tick=None, batch=None):
    """GPU 扫描：prio 优先清单（等长分桶）-> 顺序空间。支持多卡分片。
    返回 (密码或None, 已试数量, 用时)。
    prio 为 None/[] 或 progress.prio_done 时跳过优先阶段。"""
    import cupy as cp
    import numpy as np
    mods = gpu_compile(verbose=True)
    kname = GPU_KERNELS[(params["alg"], params["keyBits"])]
    n_dev = len(mods)
    if batch is None:
        batch = 50000
    total = (0 if not prio else len(prio)) + space.total()

    t0 = time.time()
    state = {"tried": 0, "found": None, "stop": False}
    lock = threading.Lock()

    def _mk_buffers(dev):
        with cp.cuda.Device(dev):
            salt_g = cp.asarray(np.frombuffer(params["salt"], dtype=np.uint8).copy())
            evi_g = cp.asarray(np.frombuffer(params["encVerifierInput"], dtype=np.uint8).copy())
            evh_g = cp.asarray(np.frombuffer(params["encVerifierHash"], dtype=np.uint8).copy())
            found = cp.full(1, -1, dtype=cp.int32)
            found_pw = cp.zeros(16, dtype=cp.uint8)
        return salt_g, evi_g, evh_g, found, found_pw

    def _gpu_tasks_all():
        # 任务流：(base, count, buf_bytes_or_None, plen, is_prio)
        if prio and not progress.prio_done:
            buckets = {}
            for pw in prio:
                b, ln = pack_pw_slot(pw)
                buckets.setdefault(ln, []).append(b)
            for L, blobs in sorted(buckets.items()):
                for s in range(0, len(blobs), batch):
                    n = min(batch, len(blobs) - s)
                    buf = bytearray(n * 16)
                    for j, b in enumerate(blobs[s:s + n]):
                        buf[j * 16:j * 16 + len(b)] = b
                    yield (s, n, bytes(buf), L, True)
        for gid, count, buf, plen in space.iter_gpu_tasks(batch):
            yield (gid, count, buf, plen, False)

    task_iter = _gpu_tasks_all()
    it_lock = threading.Lock()
    # digits: gid 连续；charset: 层间 gid 连续；wordlist: 桶乱序（不记 pos）
    buf_mode_sequential = space.mode in ("digits", "charset")

    def _next_task():
        with it_lock:
            if state["stop"]:
                return None
            try:
                return next(task_iter)
            except StopIteration:
                return None

    def _worker(dev, mod):
        try:
            fn = mod.get_function(kname)
            salt_g, evi_g, evh_g, found, found_pw = _mk_buffers(dev)
            with cp.cuda.Device(dev):
                dummy = cp.zeros(1, dtype=cp.uint8)
                spin = params["spin"]
                while True:
                    if state["stop"]:
                        break
                    task = _next_task()
                    if task is None:
                        break
                    base, count, buf, plen, is_prio = task
                    if buf is None:
                        buf_arg, use_buf = dummy, 0   # 0 = 内核自己按 base+idx 生成 6 位数字
                    else:
                        buf_arg = cp.asarray(np.frombuffer(buf, dtype=np.uint8).copy())
                        use_buf = 1
                    blocks = (count + 255) // 256
                    fn((blocks,), (256,), (salt_g, evi_g, evh_g, spin, base, count,
                                        buf_arg, plen, use_buf, found, found_pw))
                    cp.cuda.runtime.deviceSynchronize()
                    with lock:
                        state["tried"] += count
                        # 断点进度：digits/charset 的 gid 连续可精确记录；
                        # wordlist 桶乱序，中断后 GPU 需重扫该文件（CPU 顺序精确）
                        if not is_prio and buf_mode_sequential:
                            progress.pos = max(progress.pos, base + count)
                            progress.maybe_save()
                        f = int(found.get()[0])
                        if f >= 0 and state["found"] is None:
                            if buf is None:
                                state["found"] = "%06d" % f
                            else:
                                raw = bytes(found_pw.get())[:15].split(b"\x00")[0]
                                state["found"] = raw.decode("utf-8", "replace")
                            state["stop"] = True
                    if on_tick and state["tried"] > 0:
                        on_tick(state["tried"], time.time() - t0)
        except Exception as ex:
            with lock:
                if not state.get("err"):
                    state["err"] = ex
                    state["stop"] = True

    threads = [threading.Thread(target=_worker, args=(d, m), daemon=True)
               for d, m in enumerate(mods)]
    for th in threads:
        th.start()
    while any(th.is_alive() for th in threads):
        time.sleep(0.05)
    for th in threads:
        th.join()
    if state.get("err"):
        raise state["err"]

    # prio 阶段完整跑完（未中断）则记档
    if prio and not progress.prio_done and state["found"] is None:
        progress.prio_done = True
        progress.save()
    return state["found"], state["tried"], time.time() - t0

# ===========================================================================
#  第十一部分：解密导出（Office / ZIP）与产物验证
# ===========================================================================

def decrypt_document(src, password, out_path, p):
    """Agile 解密导出（v1.2：有 cryptography 时全量走 C 实现，大文件提速百倍）"""
    key = derive_secret_key(password, p)
    with CFBReader(src) as c:
        packed = c.read_stream("EncryptedPackage", smart_package=True)
    total = struct.unpack("<Q", packed[:8])[0]
    body = packed[8:]
    hasher = HASHERS[p["keyDataAlg"]]
    out = bytearray()
    seg = 4096
    idx = 0
    off = 0
    while off < len(body) and len(out) < total:
        iv = hasher(p["keyDataSalt"] + struct.pack("<I", idx)).digest()[:16]
        chunk = body[off:off + seg]
        if len(chunk) % 16:
            chunk += b"\0" * (16 - len(chunk) % 16)
        out += fast_cbc_decrypt(chunk, key, iv)
        off += seg
        idx += 1
    with open(out_path, "wb") as f:
        f.write(bytes(out[:total]))
    return out_path


def decrypt_document_std(src, password, out_path, p):
    """Standard/CryptoAPI 加密的解密导出"""
    hasher = hashlib.sha1
    h = hasher(p["salt"] + password.encode("utf-16-le")).digest()
    for i in range(p["spin"]):
        h = hasher(struct.pack("<I", i) + h).digest()
    key = derive_std_key_from_h(h, p["keySize"] // 8)
    with CFBReader(src) as c:
        packed = c.read_stream("EncryptedPackage", smart_package=True)
    total = struct.unpack("<I", packed[:4])[0]
    body = packed[8:]
    if p["cipher"] == "RC4":
        data = rc4_crypt(key, body)
    else:
        data = fast_ecb_decrypt(body, key)
    with open(out_path, "wb") as f:
        f.write(data[:total])
    return out_path


def _zip_decompress(data, method):
    if method == 8:
        return zlib.decompress(data, -15)
    if method == 12:
        import bz2
        return bz2.decompress(data)
    if method == 14:
        import lzma
        return lzma.decompress(data)
    return data


def decrypt_zip(src, password, out_path):
    """ZIP 解密导出：ZipCrypto 走标准库 pwd；WinZip AES 手动解 CTR + HMAC 校验"""
    pw = password.encode("utf-8")
    with zipfile.ZipFile(src) as zin:
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for zinfo in zin.infolist():
                if not (zinfo.flag_bits & 0x1):
                    zout.writestr(zinfo.filename, zin.read(zinfo))
                    continue
                data_off, extra = _zip_read_local_header(zin, zinfo)
                if data_off is None:
                    raise RuntimeError("读取 %s 的 local header 失败" % zinfo.filename)
                strength = _parse_aes_extra(extra) or _parse_aes_extra(zinfo.extra)
                if strength is None:
                    # ZipCrypto：标准库直接支持
                    plain = zin.read(zinfo, pwd=pw)
                    zout.writestr(zinfo.filename, plain)
                    continue
                keybits = _AES_KEY_LEN[strength]
                salt_len = _AES_SALT_LEN[strength]
                with open(src, "rb") as f:
                    f.seek(data_off)
                    raw = f.read(zinfo.compress_size)
                if len(raw) < salt_len + 12:
                    raise RuntimeError("AES 数据不完整")
                salt = raw[:salt_len]
                cipher = raw[salt_len + 2:zinfo.compress_size - 10]
                hmac_tail = raw[zinfo.compress_size - 10:]
                dk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000, 2 * keybits + 2)
                enc_key, auth_key = dk[:keybits], dk[keybits:2 * keybits]
                import hmac as _hmac
                if _hmac.new(auth_key, cipher, hashlib.sha1).digest()[:10] != hmac_tail:
                    raise RuntimeError("HMAC 校验失败（密码可能对个别条目不正确）")
                if has_crypto():
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    ctr = modes.CTR(b"\x00" * 15 + b"\x01")
                    dec = Cipher(algorithms.AES(enc_key), ctr).decryptor()
                    comp = dec.update(cipher) + dec.finalize()
                else:
                    raise RuntimeError("WinZip AES 导出需要 cryptography（可自动安装）")
                plain = _zip_decompress(comp, zinfo.compress_type)
                zout.writestr(zinfo.filename, plain)
    return out_path


def verify_export(out_path):
    """产物完整性验证：v1.1 只查 PK 头；v1.2 用 zipfile 完整打开验证"""
    try:
        with open(out_path, "rb") as f:
            head = f.read(2)
        if head != b"PK":
            return False, "产物不是 zip（请核对）"
        with zipfile.ZipFile(out_path) as zf:
            if not zf.namelist():
                return False, "zip 内没有条目"
        return True, None
    except Exception as ex:
        return False, "zip 结构异常：%r" % (ex,)


def unique_out(path, suffix):
    """输出路径冲突处理：已存在时自动加 (1)/(2)，不静默覆盖"""
    stem, ext = os.path.splitext(path)
    out = stem + suffix + ext
    i = 1
    while os.path.exists(out):
        out = "%s%s(%d)%s" % (stem, suffix, i, ext)
        i += 1
    return out


# ===========================================================================
#  第十二部分：文件分析与主流程
# ===========================================================================

VERIFY_FNS = {
    "xor": verify_xor_doc,
    "pdf_r2": verify_pdf_rc4,
    "pdf_r3": verify_pdf_rc4,
    "pdf_r4_aes": verify_pdf_aesv2,
    "pdf_r6": verify_pdf_r6,
    "zip_crypto": verify_zip_crypto,
    "zip_aes": verify_zip_aes,
}

CHUNK_BY_KIND = {
    "agile": 25, "std": 25, "pdf_r6": 20,
    "pdf_r2": 200, "pdf_r3": 200, "pdf_r4_aes": 120,
    "zip_crypto": 2000, "zip_aes": 2000, "xor": 20000,
}

EST_PER_PW = {
    "agile": 0.063, "std": 0.020, "xor": 0.000003,
    "pdf_r2": 0.00006, "pdf_r3": 0.00006, "pdf_r4_aes": 0.00012,
    "pdf_r6": 0.004, "zip_crypto": 0.000015, "zip_aes": 0.00002,
}

KIND_DESC = {
    "agile": "Office Agile 加密", "std": "Office Standard/CryptoAPI 加密",
    "xor": "Office 97-2003 XOR 混淆", "pdf_r2": "PDF RC4-40 (R2)",
    "pdf_r3": "PDF RC4-128 (R3/R4)", "pdf_r4_aes": "PDF AES-128 (R4)",
    "pdf_r6": "PDF AES-256 (R6)", "zip_crypto": "ZIP ZipCrypto",
    "zip_aes": "ZIP WinZip AES",
}


class SpeedEstimator:
    """运行时滑动窗口测速：替代 v1.1 写死的 RTX 5060 经验值"""

    def __init__(self):
        self.hist = []
        self.speed = 0.0

    def tick(self, done, el):
        self.hist.append((el, done))
        if len(self.hist) > 10:
            self.hist.pop(0)
        if len(self.hist) >= 3:
            t1, d1 = self.hist[0]
            t2, d2 = self.hist[-1]
            if t2 - t1 >= 0.8:
                self.speed = (d2 - d1) / (t2 - t1)

    @property
    def ready(self):
        return self.speed > 0


def banner():
    print("=" * 68)
    print("  %s文档密码破译器  v%s%s" % (C.CYN, VERSION, C.R))
    print("  Office(docx/xlsx/pptx/doc) · PDF · ZIP  |  CPU 多进程 + NVIDIA GPU")
    print("  %s仅供找回本人文件密码使用%s" % (C.DIM, C.R))
    print("=" * 68)


def analyse(path):
    """返回 (kind, params)。kind: agile/std/xor/pdf_*/zip_*/plain/unknown
    v1.2：不再把无 EncryptionInfo 的 CFB 当异常崩溃，能识别未加密旧版 doc。"""
    with open(path, "rb") as f:
        sig = f.read(8)
    if sig[:2] == b"PK":
        k, p = parse_zip(path)
        if k:
            return k, p
        return "plain", None
    if sig[:4] == b"%PDF":
        k, p_or_err = parse_pdf(path)
        if k:
            return k, p_or_err
        return "unknown", p_or_err
    if sig != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "unknown", None
    try:
        c = CFBReader(path)
    except CFBError:
        return "unknown", None
    try:
        if c.has_stream("EncryptionInfo"):
            ei = c.read_stream("EncryptionInfo")
            ver = struct.unpack("<HH", ei[:4])
            if ver == (4, 4):
                p = parse_agile(ei)
                if p:
                    return "agile", p
            if ver[0] in (2, 3, 4):
                p = parse_standard(ei)
                if p:
                    return "std", p
            return "unknown", None
        # 无 EncryptionInfo：可能是未加密旧版 doc/xls，也可能是 XOR 混淆
        if c.has_stream("WordDocument"):
            head = c.read_stream("WordDocument")[:16]
            if head[:2] == b"\xa5\xec":
                return "plain", None
            return "xor", {"fib_head": head, "src": path}
        if c.has_stream("Workbook") or c.has_stream("PowerPoint Document"):
            return "plain", None
        return "unknown", None
    finally:
        c.close()


def fmt_progress(done, total, est, el, tag=""):
    pct = done / total if total else 0
    width = 36
    fill = int(pct * width)
    bar = "#" * fill + "." * (width - fill)
    if est.ready:
        eta = (total - done) / est.speed
        spd = "速度 %s/秒" % format(int(est.speed), ",")
        eta_s = human(eta)
    else:
        spd, eta_s = "测速中", "--"
    return (("\r%s [%s] %5.2f%%  %s/%s  %s  已用 %s  剩余 %s   ")
            % (tag, bar, pct * 100, format(done, ","), format(total, ","),
               spd, human(el), eta_s)).ljust(100)


def verify_main(kind, params, pw):
    """主进程复核：优先 msoffcrypto（Office），其次内置实现"""
    if kind in ("agile", "std"):
        try:
            if try_import("msoffcrypto"):
                import msoffcrypto
                with open(params["_path"], "rb") as f:
                    of = msoffcrypto.OfficeFile(f)
                    if hasattr(of, "verify_password"):
                        return True, "msoffcrypto", bool(of.verify_password(pw))
                    of.load_key(password=pw)
                    return True, "msoffcrypto", True
        except Exception as ex:
            if type(ex).__name__ == "InvalidKeyError":
                return True, "msoffcrypto", False
    if kind == "agile":
        ok = verify_password_fast(pw, params["salt"], params["spin"],
                                  HASHERS[params["alg"]], params["keyBits"] // 8,
                                  params["encVerifierInput"], params["encVerifierHash"])
    elif kind == "std":
        ok = verify_std_fast(pw, params)
    else:
        ok = VERIFY_FNS[kind](pw, params)
        # ZIP 弱校验位复核加强：完整解密确认，假阳性绝不报告
        if ok and kind == "zip_crypto":
            ok = confirm_zip_crypto(pw, params)
        elif ok and kind == "zip_aes":
            ok = confirm_zip_aes(pw, params)
    return False, "内置校验", ok


def expand_files(args_files):
    """多文件 / 目录 / 通配符展开"""
    out, seen = [], set()
    for p in args_files:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if fn.lower().endswith((".doc", ".docx", ".xls", ".xlsx",
                                            ".ppt", ".pptx", ".pdf")):
                        fp = os.path.join(root, fn)
                        if fp not in seen:
                            seen.add(fp)
                            out.append(fp)
        elif any(ch in p for ch in "*?["):
            for m in sorted(glob.glob(p)):
                if os.path.isfile(m) and m not in seen:
                    seen.add(m)
                    out.append(m)
        elif os.path.isfile(p):
            if p not in seen:
                seen.add(p)
                out.append(p)
        else:
            print("%s  ! 跳过不存在的路径：%s" % (" " * 3, p))
    return out


def clamp_range(args):
    if args.start < 0 or args.end > TOTAL_SPACE or args.start >= args.end:
        # 边界校验：v1.1 传负数/越界会静默产生错误任务
        raise SystemExit("--start/--end 必须满足 0 <= start < end <= 999999")
    return args.start, args.end


def show_info(path, kind, params):
    print("  文件：%s" % path)
    print("  大小：%.2f MB" % (os.path.getsize(path) / 1048576.0))
    print("  类型：%s" % KIND_DESC.get(kind, kind))
    if kind == "agile" and params:
        print("  算法：AES-%d / %s / 迭代 %d 次 / blockSize %d" % (
            params["keyBits"], params["alg"], params["spin"], params["blockSize"]))
        print("  数据区：AES-%d / %s" % (params["keyDataKeyBits"], params["keyDataAlg"]))
        gpu_ok, why = gpu_check_support(kind, params)
        print("  GPU 加速：%s" % ("支持（内核 %s）" % GPU_KERNELS.get(
            (params["alg"], params["keyBits"]), "?") if gpu_ok else why))
    elif kind == "std" and params:
        print("  算法：%s-%d / SHA1 / 迭代 %d 次" % (
            params["cipher"], params["keySize"], params["spin"]))
        print("  GPU 加速：不支持（Standard 走 CPU）")
    elif kind in VERIFY_FNS:
        extra = ""
        if kind.startswith("pdf") and params:
            extra = "（V=%s R=%s length=%s）" % (params.get("V"), params.get("R"), params.get("length"))
        print("  GPU 加速：不支持（%s 走 CPU，速度足够）%s" % (KIND_DESC.get(kind, kind), extra))


def check_deps_cmd(args):
    print("依赖体检：\n")
    gpus, smi_err = nvidia_smi_probe()
    if gpus:
        for name, drv, cc in gpus:
            print("  GPU        : %s（驱动 %s，计算能力 %s）" % (name, drv, cc))
        print("  驱动支持   : CUDA %d.x" % cuda_from_driver(gpus[0][1]))
        pkg, pinned = cupy_package_for(cuda_from_driver(gpus[0][1]))
        print("  建议 cupy 包: %s" % (pinned or pkg))
    else:
        print("  GPU        : 未检测到（%s）" % (smi_err or "无"))
    print("  cupy       : %s" % ("已安装" if try_import("cupy") else "未安装"))
    print("  cryptography : %s（AES 导出/ PDF R6 提速）" % ("已安装" if try_import("cryptography") else "未安装"))
    print("  msoffcrypto : %s（Office 复核）" % ("已安装" if try_import("msoffcrypto") else "未安装"))
    print("  Python     : %s" % sys.version.split()[0])
    print("  解释器     : %s" % sys.executable)
    print("\nGPU 探测：")
    ok, desc = gpu_probe(mirror=args.mirror, auto_install=False)
    print("  %s" % ("可用 -> " + desc if ok else desc))
    return 0


def crack_one(path, args, space, pool_pw_cache=None):
    """破解单文件。返回 (密码或None, kind, params)"""
    kind, params = analyse(path)
    if kind == "plain":
        print("\n  该文件未加密，无需破解")
        return None, kind, params
    if kind == "unknown":
        print("\n  %s无法识别的加密格式：%s%s" % (C.YEL, params or "未知结构", C.R))
        print("  可尝试 pip install msoffcrypto-tool 后用其命令行处理")
        return None, kind, params
    params["_path"] = path

    show_info(path, kind, params)

    # 批量模式：先用已知的密码池试
    if pool_pw_cache:
        for pw in pool_pw_cache:
            if kind in VERIFY_FNS:
                if VERIFY_FNS[kind](pw, params):
                    return pw, kind, params
            elif kind == "agile" and verify_password_fast(
                    pw, params["salt"], params["spin"], HASHERS[params["alg"]],
                    params["keyBits"] // 8, params["encVerifierInput"],
                    params["encVerifierHash"]):
                return pw, kind, params
            elif kind == "std" and verify_std_fast(pw, params):
                return pw, kind, params

    # ---- 构建搜索空间与优先清单 ----
    if space.mode == "digits":
        prio = [] if args.seq else build_priority_list()
    elif space.mode == "charset":
        prio = [""]      # 空密码值得先试
    else:
        prio = []

    use_gpu = False
    if not args.no_gpu:
        gpu_ok, why = gpu_check_support(kind, params)
        if gpu_ok:
            use_gpu = True
        elif kind == "agile":
            print("  %s%s%s" % (C.YEL, why, C.R))

    workers = args.workers or max(1, (os.cpu_count() or 4))
    total_work = len(prio) + space.total()

    progress = Progress(path, progress_sig(path, kind, params, space),
                         enabled=(args.resume is not False))
    resumed = False
    if progress.loaded:
        if not progress.prio_done and prio:
            scanned = "优先清单 %s/%s + 空间 %s" % (
                format(progress.prio_pos, ","), format(len(prio), ","),
                format(progress.pos, ","))
        else:
            scanned = format(progress.pos, ",")
        ans = _ask("  检测到未完成进度（已扫 %s），继续吗？(Y/n) "
                   % scanned).strip().lower()
        if args.resume is False or ans in ("n", "no"):
            progress.clear()
            progress = Progress(path, progress_sig(path, kind, params, space), enabled=False)
        else:
            resumed = True
            space_full = space          # 裁剪前的完整空间
            # 空间裁剪到剩余部分：digits 直接改 start；charset 按 gid 扣减已扫前缀
            if space.mode == "digits" and progress.pos > space.start:
                space = Space("digits", start=progress.pos, end=space.end)
            prio_left = 0 if progress.prio_done else (len(prio) - progress.prio_pos)
            if space.mode == "charset":
                space_left = max(0, space.total() - progress.pos)
            else:
                space_left = space.total()
            total_work = prio_left + space_left
            if total_work <= 0:
                # 上一轮把整个空间扫完了但没命中，进度文件不会被清，
                # 续扫会一个任务都不发、几秒后直接"未找到"。这里回退成完整重扫。
                print("  （上次已扫完整个空间但未命中，本轮从头重扫）")
                progress.clear()
                progress = Progress(path, progress_sig(path, kind, params, space_full),
                                    enabled=False)
                space, resumed, total_work = space_full, False, len(prio) + space_full.total()

    est = SpeedEstimator()
    if use_gpu:
        gpu_ok_probe, desc = gpu_probe(mirror=args.mirror,
                                       auto_install=args.auto_install)
        if not gpu_ok_probe:
            print("  GPU 不可用（%s）-> 回退 CPU" % desc)
            use_gpu = False

    speed_hint = EST_PER_PW.get(kind, 0.05)
    if kind == "agile":
        hash_factor = {"SHA1": 0.75, "SHA256": 0.9, "SHA384": 1.05, "SHA512": 1.0}.get(
            params["alg"], 1.0)
        speed_hint *= (params["spin"] / 100000.0) * hash_factor
    est_cpu = workers * (1.0 / speed_hint) * (0.85 if workers <= 8 else 0.55)

    print("\n  搜索空间：%s（%s 个密码）%s" % (
        space.describe(), format(total_work, ","),
        "  [续扫自 %s]" % format(progress.pos, ",") if resumed else ""))
    print("  引擎：%s" % ("GPU 加速" if use_gpu else "CPU × %d 进程" % workers))
    if not use_gpu:
        print("  粗估耗时：约 %s（以实测速度为准）" % human(total_work / max(est_cpu, 1e-9)))
    if prio and not progress.prio_done:
        left = len(prio) - (progress.prio_pos if resumed else 0)
        print("  先扫 %s 个高频密码+生日，再全空间顺序" % format(left, ","))
    print("  " + "-" * 64)

    t_start = time.time()
    found = None

    if use_gpu:
        try:
            def _tick(tried, el):
                est.tick(tried, el)
                _say(fmt_progress(tried, total_work, est, el, "[GPU] "))
            found, done, _gel = gpu_scan(params, prio, space, progress,
                                         on_tick=_tick, batch=args.batch)
            _say(fmt_progress(done, total_work, est, time.time() - t_start), newline=True)
        except KeyboardInterrupt:
            print("\n\n  用户中断。")
            progress.save()
            return None, kind, params
        except Exception as ex:
            print("\n  %sGPU 执行出错，切换 CPU 模式：%s%s" % (C.YEL, _strip_ex(ex), C.R))
            print("  （断点已保存，CPU 从未完成处继续，不重复已扫部分）")
            use_gpu = False
            # 注意：不重置 progress，CPU 从断点续扫
            t_start = time.time()

    if not use_gpu:
        if kind in ("agile", "std"):
            cfg = dict(params)
            cfg["kind"] = kind
            cfg["use_crypto_aes"] = has_crypto() and kind == "agile"
        else:
            # xor / pdf / zip：worker 端直接拿原始 params + 校验函数
            cfg = {"kind": kind, "params": params}
        chunk = CHUNK_BY_KIND.get(kind, 25)
        ctx = mp.get_context("spawn")
        pool = None
        prio_total = len(prio) if (prio and not progress.prio_done) else 0
        completed_prio = {}
        completed = {}
        done = 0

        def _tasks():
            if prio and not progress.prio_done:
                for s in range(progress.prio_pos, len(prio), chunk):
                    yield ("P", s, prio[s:s + chunk])
            # resume：跳过空间中 gid < progress.pos 的已扫前缀（wordlist 桶乱序不记进度）
            pos = progress.pos if space.mode in ("digits", "charset") else 0
            for t in space.iter_tasks(chunk):
                if t[0] == "D":
                    s, e = t[1], t[2]
                    if e <= pos:
                        continue
                    if s < pos:
                        s = pos
                    yield ("D", s, (s, e))
                else:
                    gs, lst = t[1], t[2]
                    if pos and gs + len(lst) <= pos:
                        continue
                    if pos and gs < pos:
                        gs, lst = pos, lst[pos - t[1]:]
                    yield ("S", gs, lst)

        last = 0.0
        try:
            # spawn 启动几十个进程可能耗时数秒，启动期 Ctrl+C 也要走保存路径
            pool = ctx.Pool(workers, initializer=_worker_init, initargs=(cfg,))
            for tag, gid_start, n, hit in pool.imap_unordered(_worker_check, _tasks(), chunksize=1):
                done += n
                if tag == "P":
                    # prio 也按前缀推进（imap_unordered 乱序完成，连续段才可推进）
                    completed_prio[gid_start] = n
                    while progress.prio_pos in completed_prio:
                        progress.prio_pos += completed_prio.pop(progress.prio_pos)
                    if prio_total and progress.prio_pos >= prio_total:
                        progress.prio_done = True
                    progress.maybe_save()
                else:
                    completed[gid_start] = n
                    while progress.pos in completed:
                        progress.pos += completed.pop(progress.pos)
                    progress.maybe_save()
                now = time.time()
                if now - last > PROGRESS_REFRESH:
                    last = now
                    est.tick(done, now - t_start)
                    tagtxt = "[1/2 优先]" if tag == "P" else "[2/2 顺序]"
                    if prio_total == 0:
                        tagtxt = "[扫描]"
                    _say(fmt_progress(done, total_work, est, now - t_start, tagtxt + " "))
                if hit:
                    found = hit
                    break
            est.tick(done, time.time() - t_start)
            _say(fmt_progress(done, total_work, est, time.time() - t_start), newline=True)
        except KeyboardInterrupt:
            print("\n\n  用户中断。已完成 %s / %s（进度已保存，重跑可续扫）"
                  % (format(done, ","), format(total_work, ",")))
            progress.save()
            found = None
        finally:
            if pool is not None:
                try:
                    pool.terminate()
                    pool.join()
                except Exception:
                    pass

    if found is None:          # 注意：空密码是合法结果，不能用 if not found
        return None, kind, params

    progress.clear()
    cost = time.time() - t_start
    print("\n" + "=" * 68)
    print("  %s★ 密码找到：%s%s" % (C.GRN, found, C.R))
    print("  用时：%s" % human(cost))
    print("=" * 68)
    if clipboard_copy(found):
        print("  （已复制到剪贴板）")

    # ---- 复核 ----
    print("\n  正在复核...")
    maybe_install_msoffcrypto_once(args)
    used_mso, src_name, ok = verify_main(kind, params, found)
    mark = "通过" if ok else "未通过"
    print("  %s：%s%s%s" % (src_name, C.GRN if ok else C.RED, mark, C.R))
    if not ok:
        print("  ! 复核未通过（极小概率假阳性），建议重跑确认")
    return found, kind, params


_MS_ASKED = {"done": False}


def maybe_install_msoffcrypto_once(args):
    """msoffcrypto 复核依赖：只在缺失时询问一次"""
    if _MS_ASKED["done"] or try_import("msoffcrypto"):
        return
    _MS_ASKED["done"] = True
    maybe_install("msoffcrypto", ["msoffcrypto-tool"],
                  "  复核建议安装 msoffcrypto-tool（第三方交叉验证，可选）",
                  args.mirror, args.auto_install)


def export_decrypted(path, kind, params, password, auto=False):
    if kind == "xor":
        print("  XOR 混淆文档暂不支持直接导出（可用 Word 打开时另存）")
        return None
    if kind.startswith("pdf_"):
        print("  PDF 解密导出请使用 pikepdf/qpdf（已知密码）或 Acrobat 移除安全限制")
        return None
    if kind.startswith("zip_"):
        out = unique_out(path, "_已解密")
        decrypt_zip(path, password, out)
        ok, err = verify_export(out)
        print("  已输出：%s%s" % (out, "" if ok else "  (警告：%s)" % err))
        return out
    if kind == "agile":
        if not has_crypto() and os.path.getsize(path) > 2 * 1024 * 1024:
            print("  提示：未安装 cryptography，大文件纯 Python 解密较慢")
        out = unique_out(path, "_已解密")
        decrypt_document(path, password, out, params)
    elif kind == "std":
        out = unique_out(path, "_已解密")
        decrypt_document_std(path, password, out, params)
    else:
        return None
    ok, err = verify_export(out)
    print("  已输出：%s%s" % (out, "" if ok else "  (警告：%s)" % err))
    return out


def build_argparser():
    ap = argparse.ArgumentParser(
        add_help=True,
        description="文档密码破译器 v%s：Office(doc/docx/xls/xlsx/ppt/pptx) + PDF + ZIP" % VERSION,
        epilog="示例：\n"
               "  %(prog)s -f 秘密.docx\n"
               "  %(prog)s -f \"*.pdf\" --wordlist rockyou.txt\n"
               "  %(prog)s -f 加密目录/ --charset digits --min-len 4 --max-len 8\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", "-f", nargs="+", default=None,
                    help="目标文件/目录/通配符，可多个（批处理）")
    ap.add_argument("--workers", "-w", type=int, default=None, help="CPU 进程数")
    ap.add_argument("--seq", action="store_true", help="纯顺序模式，不做生日/高频预判")
    ap.add_argument("--start", type=int, default=0, help="数字空间起点（0-999999）")
    ap.add_argument("--end", type=int, default=TOTAL_SPACE, help="数字空间终点（0-999999）")
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK, help="（兼容保留）")
    ap.add_argument("--no-gpu", action="store_true", help="禁用 GPU，仅用 CPU 多进程")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    ap.add_argument("--resume", dest="resume", action="store_true", default=None,
                    help="强制续扫（默认自动询问）")
    ap.add_argument("--no-resume", dest="resume", action="store_false",
                    help="忽略已有进度从头扫")
    ap.add_argument("--charset", default=None,
                    help="字符集：digits/lower/upper/alpha/alnum/hex 或自定义字符串")
    ap.add_argument("--min-len", type=int, default=6, help="charset 模式最小长度")
    ap.add_argument("--max-len", type=int, default=6, help="charset 模式最大长度")
    ap.add_argument("--wordlist", default=None, help="字典文件（每行一个密码，#注释）")
    ap.add_argument("--batch", type=int, default=50000, help="GPU 每批密码数")
    ap.add_argument("--info", action="store_true", help="只显示加密参数，不破解")
    ap.add_argument("--check-deps", action="store_true", help="依赖体检并退出")
    ap.add_argument("--mirror", default=None,
                    help="pip 镜像：tuna / aliyun / douban 或完整 URL")
    ap.add_argument("--yes", "-y", dest="auto_install", action="store_true",
                    help="自动安装缺失依赖，不询问")
    ap.add_argument("--no-install", dest="auto_install", action="store_false",
                    help="不自动安装任何依赖")
    return ap


def main():
    args = build_argparser().parse_args()
    _init_console()
    C.init(no_color=args.no_color)

    if args.check_deps:
        return check_deps_cmd(args)

    banner()

    files = expand_files(args.file) if args.file else None
    if files is None:
        print("\n请输入要破译的文件完整路径（可拖拽，多个文件用空格分隔）：")
        raw = _ask("> ").strip()
        files = expand_files([x.strip().strip('"').strip("'")
                              for x in raw.split() if x.strip()]) if raw else []
    if not files:
        print("\n未提供文件路径。")
        _pause()
        return

    if args.info:
        for p in files:
            kind, params = analyse(p)
            print("")
            show_info(p, kind, params if isinstance(params, dict) else {})
        _pause()
        return

    clamp_range(args)
    space = make_space(args)
    batch_mode = len(files) > 1

    results = []
    pw_pool = []
    for path in files:
        print("\n" + "=" * 68)
        print("  目标 %d/%d：%s" % (len(results) + 1, len(files), path))
        pw, kind, params = crack_one(path, args, space, pool_pw_cache=pw_pool)
        if pw is not None:
            if pw not in pw_pool:
                pw_pool.append(pw)
            results.append((path, pw, kind, params))
            if batch_mode:
                export_decrypted(path, kind, params, pw, auto=True)
        elif kind == "plain":
            results.append((path, None, kind, params))
        else:
            results.append((path, None, kind, params))

    print("\n" + "=" * 68)
    print("  %s汇总%s（%d 个文件）" % (C.BLD, C.R, len(results)))
    ok_n = 0
    for path, pw, kind, params in results:
        if pw is not None:
            ok_n += 1
            print("  %s✔%s %s -> %s%s%s" % (C.GRN, C.R, os.path.basename(path),
                                          C.GRN, pw, C.R))
        elif kind == "plain":
            print("  %s-%s %s（未加密）" % (C.DIM, C.R, os.path.basename(path)))
        else:
            print("  %s✘%s %s（未找到）" % (C.RED, C.R, os.path.basename(path)))
    print("  破解成功：%d/%d" % (ok_n, len(results)))

    # 单文件模式：询问是否导出
    if not batch_mode and len(results) == 1 and results[0][1] is not None:
        path, pw, kind, params = results[0]
        ans = _ask("\n是否解密并另存一份副本？(Y/n) ").strip().lower()
        if ans in ("", "y", "yes", "是"):
            export_decrypted(path, kind, params, pw)
    print("\n完成。")
    _pause()


if __name__ == "__main__":
    mp.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        print("\n已中断。")
    except SystemExit:
        raise
    except Exception:
        import traceback
        traceback.print_exc()
        _pause("\n出错了，按回车退出...")
