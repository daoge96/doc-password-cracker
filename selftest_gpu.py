# -*- coding: utf-8 -*-
"""
GPU 自检：用"已知密码"的合成 Agile 参数，检查破解器的各条链路是否真的能命中。

背景：主脚本曾在 GPU 的 digits 通道上有一个"扫了 100 万个密码却一个都没测"的
bug（内核按 pwbuf 是否为空指针分支，而主机端传的是 1 字节 dummy）。
本自检 20 秒内就能发现这类问题。

用法：python selftest_gpu.py [主脚本路径]
"""
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, "bcrack.py")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load(path):
    spec = importlib.util.spec_from_file_location("bcrack_selftest", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


m = load(MAIN)
print("被测脚本：%s  (v%s)" % (MAIN, m.VERSION))


def enc_cbc(data, key, iv):
    out, prev = bytearray(), iv[:16]
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        cur = m.aes_encrypt_block(blk, key)
        out += cur
        prev = cur
    return bytes(out)


SALT = os.urandom(16)
SPIN = 2000
ALG = "SHA512"
KEYBITS = 256
HASHER = m.HASHERS[ALG]


def craft(pw):
    """按 Agile 规范造一份"密码就是 pw"的 EncryptionInfo 参数"""
    h = m.first_iterate(pw, SALT, SPIN, HASHER)
    k1 = HASHER(h + m.BLK_VERIFIER).digest()[:KEYBITS // 8]
    verifier = os.urandom(16)
    evi = enc_cbc(verifier, k1, SALT)
    k2 = HASHER(h + m.BLK_VERIFIER_HASH).digest()[:KEYBITS // 8]
    evh = enc_cbc(HASHER(verifier).digest(), k2, SALT)
    return {"salt": SALT, "spin": SPIN, "alg": ALG, "keyBits": KEYBITS,
            "encVerifierInput": evi, "encVerifierHash": evh}


class Stub:
    """gpu_scan 需要的 progress 最小接口"""

    def __init__(self):
        self.prio_done = False
        self.pos = 0

    def maybe_save(self, force=False):
        pass

    def save(self):
        pass


fails = []


def check(label, got, want):
    ok = got == want
    if not ok:
        fails.append(label)
    print("  [%s] %-42s got=%-12r want=%r"
          % ("PASS" if ok else "FAIL", label, got, want))


print()
print("1) 合成参数本身的校验函数（基准）")
_p = craft("123456")
check("SHA512 目标自校验",
      m.verify_password_fast("123456", SALT, SPIN, HASHER, KEYBITS // 8,
                             _p["encVerifierInput"], _p["encVerifierHash"]), True)
check("SHA512 错误密码应为 False",
      m.verify_password_fast("999999", SALT, SPIN, HASHER, KEYBITS // 8,
                             _p["encVerifierInput"], _p["encVerifierHash"]), False)

print()
print("2) GPU：digits 通道必须真的命中（曾经全空间扫不出任何密码）")
try:
    t0 = time.time()
    got = m.gpu_scan(craft("123456"), [], m.Space("digits", 0, 1000000), Stub())[0]
    check("digits 命中 123456（%.0f 秒）" % (time.time() - t0), got, "123456")
    check("digits 命中 000007（前导零）",
          m.gpu_scan(craft("000007"), [], m.Space("digits", 0, 1000000), Stub())[0],
          "000007")
    check("digits 区间 400000-600000 命中 500000",
          m.gpu_scan(craft("500000"), [], m.Space("digits", 400000, 600000), Stub())[0],
          "500000")
except ImportError:
    print("  (跳过：没装 cupy)")

print()
print("3) GPU：优先清单通道（含空密码）")
for cand in ["", "5201314", "19900101"]:
    check("prio %-12r" % cand,
          m.gpu_scan(craft(cand), [cand], m.Space("digits", 0, 100), Stub())[0], cand)

print()
print("4) GPU：字典通道（含 >15 字节长条目，曾会撑爆 16 字节槽）")
sp = m.Space("wordlist", wordlist=["a" * 20, "b" * 17, "123456", "5201314"])
for cand in ["123456", "5201314"]:
    check("wordlist %-12r" % cand, m.gpu_scan(craft(cand), [], sp, Stub())[0], cand)

print()
print("5) CPU：digits 通道（对照组）")
cfg = dict(craft("123456"))
cfg.update({"kind": "agile", "use_crypto_aes": False})
m._worker_init(cfg)
check("CPU digits 命中 123456", m._worker_check(("D", 123000, (123000, 124000)))[3],
      "123456")

print()
print("=" * 56)
print("全部通过" if not fails else "有 %d 项失败：%s" % (len(fails), "，".join(fails)))
sys.exit(1 if fails else 0)
