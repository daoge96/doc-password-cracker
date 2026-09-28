<div align="center">

# doc-password-cracker

**文档密码破译器** — 找回你自己加密文档的密码

Office (doc / docx / xls / xlsx / ppt / pptx) · PDF · ZIP
纯 Python 标准库即可运行 · 有 N 卡自动 GPU 加速 · 断点续扫 · 可拖拽

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D4)](#-快速开始)
[![GPU](https://img.shields.io/badge/GPU-NVIDIA%20CUDA%20via%20CuPy-76B900)](#-性能实测)
[![Dependencies](https://img.shields.io/badge/third--party%20deps-0%20(optional)-brightgreen)](#-快速开始)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

### ⭐ 这个项目**非常**需要你帮忙优化 → [跳到求优化清单](#-求大家来帮忙优化)

</div>

---

## 目录

- [这是什么](#-这是什么)
- [支持的加密体系](#-支持的加密体系)
- [性能实测](#-性能实测)
- [快速开始](#-快速开始)
- [用法与参数](#-用法与参数)
- [工作原理](#-工作原理)
- [项目结构](#-项目结构)
- [自检](#-自检)
- [诚实的 bug 记录](#-诚实的-bug-记录)
- [求大家来帮忙优化](#-求大家来帮忙优化)
- [常见问题](#-常见问题)
- [免责声明](#-免责声明)

---

## 这是什么

一句话：**把加密的文档拖进来，把它忘记的密码试出来。**

很多人手上的老文档是"当年随手设了个密码"的：`123456`、生日、`520520`、QQ 号……
自己也 owns 这个文件，就是打不开了。这个工具就是干这个的 ——
不联网、不上传、纯本地暴力搜索，支持 CPU 多进程和 NVIDIA GPU 加速。

设计目标按优先级排：

1. **正确**：宁可慢，不能报错密码。命中判定全是密码学强校验（详见[工作原理](#-工作原理)），并且找到后会再用第三方库 `msoffcrypto-tool` 交叉复核一遍。
2. **零门槛**：拖进去就能跑，不需要先手动从文档里抽 hash。第三方依赖一个都不装也能跑（纯标准库实现全都有），装了会自动加速。
3. **可中断**：跑几十小时的活，Ctrl+C 断电都不怕，进度 5 秒一存，下次自动续扫。

> ⚠️ 用途声明：本工具面向"找回**你自己拥有**的文档密码"。
> 请勿用于未经授权访问他人文档。

---

## 支持的加密体系

| 文件类型 | 加密体系 | GPU |
|---|---|---|
| `.docx` `.xlsx` `.pptx` | Office 2007+ **Agile**：AES-128/192/256 × SHA1/256/384/512 | ✅ 12 个 CUDA 内核 |
| `.doc` `.xls` `.ppt` | Office 2002-2008 **Standard / CryptoAPI**：AES-128、RC4-40/128 | ❌ 走 CPU |
| `.doc` (97-2003) | **XOR 混淆**（按 [MS-OFFCRYPTO] 2.3.7 常量表） | ❌ 走 CPU |
| `.pdf` | **R2 / R3 / R4**（RC4-40/128、AES-128）、**R6**（AES-256，PDF 2.0） | ❌ 走 CPU |
| `.zip` | **ZipCrypto**、**WinZip AES**（PBKDF2-HMAC-SHA1） | ❌ 走 CPU |

暂不支持：PDF R5（AES-256 ExtLevel3，很罕见且已废弃）、7z / RAR、Office IRM 权限管理。

按照"文件结构特征"自动识别加密类型，不用你告诉它。支持单个文件、多文件、整个目录、通配符。

---

## 性能实测

在有 GPU 的情况下，Office Agile 是唯一值得上 GPU 的类型（迭代次数高、KDF 重）。

| 引擎 | 速度 | 跑完 100 万密码 |
|---|---|---|
| **GPU**（RTX 5060 Laptop 8GB） | **约 11,900 密码/秒** | **约 90 秒** |
| CPU（R9 8945HX，32 进程） | 约 171 密码/秒 | 约 97 分钟 |

> 条件：Office Agile / SHA512 / spinCount=100000。GPU 约快 **60~70 倍**。
> 速度是运行时实测的滑动平均，ETA 不用写死的经验值。

CPU 模式下线性吃满核心数；GPU 模式下多张 N 卡会自动分片并行。CUDA 内核首次运行会现场编译（约 1 分钟），之后按"源码 + 显卡架构"哈希落盘缓存，再跑秒加载。

---

## 快速开始

```bash
git clone https://github.com/daoge96/doc-password-cracker.git
cd doc-password-cracker
python bcrack.py
```

然后**把加密文件直接拖进终端**回车即可。

**依赖**：只需要 Python 3.8+，第三方包一个都不装也能跑（AES、SHA、RC4、CFB 解析全是手写的）。
以下可选依赖脚本会在需要时询问你要不要自动装：

| 可选依赖 | 作用 |
|---|---|
| `cryptography` | AES 走 C 实现，大文件解密导出快 50~100 倍；PDF R6 提速 |
| `msoffcrypto-tool` | 找到密码后的第三方交叉复核 |
| `cupy-cudaXXx` | GPU 加速（按你的驱动版本自动选 cuda11x / 12x / 13x） |

先体检一下环境也可以：

```bash
python bcrack.py --check-deps
```

---

## 用法与参数

```bash
python bcrack.py                            # 交互式，拖文件进去
python bcrack.py -f "秘密.docx"             # 直接指定文件
python bcrack.py -f "a.pdf" -f "b.zip"      # 多文件批处理
python bcrack.py -f ./加密目录/             # 目录批处理
python bcrack.py --no-gpu -w 16             # 强制纯 CPU，16 进程
python bcrack.py --start 300000 --end 700000
python bcrack.py --charset digits --min-len 4 --max-len 8
python bcrack.py --wordlist rockyou.txt
python bcrack.py --info -f "x.docx"         # 只看加密参数，不破解
python bcrack.py --resume                   # 断点续扫（默认自动检测）
```

| 参数 | 说明 |
|---|---|
| `-f, --file` | 目标文件 / 目录 / 通配符，可重复 |
| `--start` / `--end` | 数字空间范围，默认 `0` ~ `999999` |
| `--charset` | 字符集：`digits` `lower` `upper` `alpha` `alnum` `hex` 或自定义字符串 |
| `--min-len` / `--max-len` | 配合 `--charset` 的长度范围，默认 6~6 |
| `--wordlist` | 字典文件，每行一个密码，`#` 开头为注释 |
| `--seq` | 纯顺序扫，跳过"高频口令 + 生日"预判 |
| `-w, --workers` | CPU 进程数，默认吃满核心 |
| `--no-gpu` | 禁用 GPU |
| `--resume` / `--no-resume` | 强制 / 禁用续扫 |
| `--batch` | GPU 每批密码数，默认 50000 |
| `--info` | 只打印加密参数 |
| `--check-deps` | 依赖体检 |
| `--mirror` | pip 镜像：`tuna` / `aliyun` / `douban` 或完整 URL |
| `-y / --no-install` | 自动装 / 绝不装依赖 |
| `--no-color` | 关彩色 |

**断点续扫**：进度写在 `<原文件>.bcrack.json`，5 秒一存。中断、GPU 报错回退 CPU 都会保留，下次运行会问你要不要接着扫，不重复已扫部分。

---

## 工作原理

### 怎么判断"这个密码对不对"

**绝不解密整个文件来验证** —— 那太慢了。Office Agile 只需要算：

```
H0 = HASH(salt ‖ UTF16LE(password))
H  = HASH(i ‖ H)     重复 spinCount 次（通常 100000）
k1 = HASH(H ‖ BLK_VERIFIER)[:keylen]
```

然后用 `k1` 去 AES-CBC 解 `encryptedVerifierHashInput` 得到 `verifier`，
再拿 `HASH(verifier)[:16]` 和用 `k2` 解出来的 `encryptedVerifierHashValue` 前 16 字节比。
相等即命中 —— 误报概率 **2⁻¹²⁸**，实际等于不会误报。

不同加密体系各有对应的强校验（PDF 走 Algorithm 3.2 / 3.5；ZIP 因为校验位只有 16 bit 偏弱，命中后还会完整解密二次确认）。

### GPU 内核

`bcrack.py` 里内嵌了完整的 CUDA 源码（NVRTC 现场编译）：SHA-1 / SHA-256 / SHA-384 / SHA-512、
AES-128/192/256 的密钥展开与 CBC 首块解密，全部模板化展开成 12 个内核入口。
纯 Python 的等价实现在没有 GPU 时兜底。

### 先猜什么

默认不是从 `000000` 傻扫，而是先扫一张 3.7 万条的优先清单：
高频弱口令 + 1930~2030 年**全部**生日（`YYMMDD` 与 `DDMMYY` 两种写法）。
找不回密码的情况里，这两类占绝大多数。

---

## 项目结构

```
bcrack.py        主程序，单文件，约 3600 行（含内嵌 CUDA 源码）
selftest_gpu.py  20 秒自检：用"已知密码"的合成参数验证各条链路真的能命中
README.md
CHANGELOG.md
LICENSE
```

单文件是刻意的：方便直接丢给别人、方便 PyInstaller 打包成免安装 EXE。

---

## 自检

```bash
python selftest_gpu.py
```

它会临时合成一份"密码已知为 `123456`"的 Agile 加密参数，然后验证 GPU 的 digits 通道、
优先清单通道、字典通道、CPU 通道**是否真的能命中**，最后打印 PASS/FAIL 并以退出码返回。

**为什么需要它**：见下节。

---

## 诚实的 bug 记录

> 测试不是摆设。这个项目曾经有一个"看起来一切正常、实际一个密码都没测"的 bug，
> 靠肉眼盯 100 万条进度条是发现不了的。

**v1.2.1 及以前**：CUDA 内核用 `if (pwbuf)` —— 也就是"指针是否为 NULL" —— 来区分
"用现成的密码缓冲"还是"按序号现场生成 6 位数字"。但主机端在 digits 模式下传的是一个
**1 字节的 `dummy` 缓冲**（非 NULL，本意是避免传空指针）。结果：

- 内核永远走缓冲分支，**6 位数字生成逻辑成了死代码**；
- 它从一个 1 字节的分配里按 `idx*16` **越界读 16 字节**，读到的是隔壁内存的垃圾；
- 于是 `000000` ~ `999999` 这一百万个密码**一个都没被真正测试过**，
  进度条却老老实实跑到 100%，然后报"未找到"。

修复方式：内核加显式 `use_buf` 开关，不再依赖指针判空。
同批还修了另外 4 个问题，详见 [CHANGELOG.md](CHANGELOG.md)。

这也是 `selftest_gpu.py` 存在的理由 —— 它 20 秒内就能抓出这一整类"扫了却没测"的问题。

---

## 求大家来帮忙优化

**这个项目非常欢迎贡献，哪怕只改一行、报一个 bug、贴一个测试文件都算。**

作者只有一台 N 卡 Windows 机器，很多路径根本没条件覆盖。下面是**具体的、可以直接认领的**清单。
想认领哪条，开个 issue 说一声就行，不用怕重复。没写过 CUDA 也完全可以挑第一档。

### 🟢 适合第一次贡献

| # | 任务 | 说明 |
|---|---|---|
| 1 | **英文界面 / i18n** | 所有提示和 `argparse` help 都是中文硬编码，抽一张 messages 表，加 `--lang` |
| 2 | **加 CI** | GitHub Actions：跑 `selftest_gpu.py` 的 CPU 部分 + `ruff` / `pyflakes` 静态检查 |
| 3 | **把自检扩成 pytest** | 覆盖 CFB 解析、各体系 KDF、各 `verify_*` 函数，做成真单元测试 |
| 4 | **`--version` 参数** | 现在只能靠 `--check-deps` 看到版本号 |
| 5 | **进度文件生命周期** | 扫完命中就该删；扫完没命中应记 `completed` 标记，而不是留个 `pos=end` 让续扫空转 |

### 🟡 中等

| # | 任务 | 说明 |
|---|---|---|
| 6 | **GPU 支持非 ASCII 密码** | 内核目前把缓冲区字节直接当 UTF-16 码元用，**中文 / 带重音的密码在 GPU 上会算错**（CPU 是对的）。需要在核心里做 UTF-8 → UTF-16LE 转换 |
| 7 | **支持超过 15 字节的密码** | GPU 是 16 字节定长槽，超长会被截断。改成 32 字节槽或变长缓冲 |
| 8 | **charset 模式长度上限** | 内核 `h0in[46]` 写死，`--max-len > 15` 会越界 |
| 9 | **Standard / CryptoAPI 上 GPU** | 现在只有 Agile 有内核，Office 2002-2008 的老文件只能纯 CPU |
| 10 | **PDF R5 支持** | 目前直接报"暂不支持" |
| 11 | **XOR 混淆 .doc 导出** | 现在能破密码但不能导出解密副本 |
| 12 | **wordlist 模式断点精度** | GPU 下字典按长度分桶乱序跑，中断后只能整份重扫 |

### 🔴 硬骨头

| # | 任务 |
|---|---|
| 13 | **掩码攻击**（hashcat 风格 `-1 ?d?d?d?d`、自定义 charset 位） |
| 14 | **规则引擎 / 混合攻击**（字典 + 数字后缀 / 大小写变形） |
| 15 | **多 GPU 动态负载均衡**（现在是静态分片，慢卡拉后腿） |
| 16 | **内核性能优化**，目标 2~3×（共享内存、指令级并行、减少迭代链依赖） |
| 17 | **非 NVIDIA 后端**：Vulkan Compute / OpenCL，让 A 卡和核显也能加速 |
| 18 | **更多格式**：7z、RAR、BitLocker、VeraCrypt 容器 |

### 特别稀缺：测试样本

作者手头没有下面这些，**只要你有文件 + 记得密码，就是无价的测试用例**：

- Office 97-2003 的 `.doc` / `.xls` / `.ppt` 加密文件（XOR 与 RC4 两条老路径）
- PDF R5 加密文件
- WinZip AES-256 加密的 zip
- 密码含中文 / emoji 的文档
- AMD 显卡、Apple Silicon、Linux 环境下的运行报告

### 怎么参与

1. Fork → 建分支 → 改代码
2. **改完必须跑 `python selftest_gpu.py`，要全 PASS**（动了内核的话这是硬要求）
3. 提 PR，说明改了什么、怎么验证的

报 bug 时请附上这两条命令的输出（**加密参数不含密码，可以安全贴出来**）：

```bash
python bcrack.py --check-deps
python bcrack.py --info -f "你的文件"
```

不想写代码也有事可做：**star 一下、把工具转给正被加密文档卡住的人、报一个"在我机器上跑出来是这样"的结果**，都很有用。

---

## 常见问题

**会把我的文档 / 密码传到网上吗？**
不会。纯本地计算，只有自动装依赖时会联网下载 pip 包。

**会改坏原文件吗？**
不会，全程只读。导出的解密副本另存为 `xxx_已解密.docx`。

**支持中文密码吗？**
CPU 路径支持任意 Unicode。GPU 路径目前只对 ASCII 正确（见待优化 #6）。

**为什么这么慢？**
Office Agile 是**故意**设计成慢的（10 万次哈希迭代就是为了拖慢暴力搜索）。这是算法特性，不是实现问题。

**那为什么不用 hashcat？**
hashcat 更强更快，但你得先从文档里抽出 hash 喂给它（依赖 john / hashcat 的 office2john 之类工具，不同格式还不一样）。本工具直接吃原文件，拖进去就行，适合"我就要打开这一个文件"的场景。两者互补。

**跑一半断电了怎么办？**
进度存在 `<文件>.bcrack.json`，下次运行会问你要不要接着扫。

**装了 cupy 但 GPU 没被用上？**
跑 `python bcrack.py --check-deps`，它会诊断原因（驱动过旧 / 架构不支持 / DLL 被 Windows 智能应用控制拦截）。

---

## 免责声明

本工具仅用于找回**你自己拥有**的文档密码。请勿用于未经授权访问他人文档。

---

## License

[MIT](LICENSE) © daoge96
