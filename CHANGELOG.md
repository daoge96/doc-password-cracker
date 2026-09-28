# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.2.2] - 2026-09-28

一次"实际扫描完全无效但表面上毫无异常"的修复。起因是一份 6 位纯数字密码的 docx：
GPU 把 000000~999999 整整一百万条跑完（进度条 100%），却报"未找到"。

### 修复

- **GPU 6 位纯数字通道完全失效（致命）**：CUDA 内核用 `if (pwbuf)` 即"指针是否为 NULL"
  来区分"用现成缓冲"与"按 base+idx 现场生成 6 位数字"，而主机端 digits 模式传的是
  1 字节的 `dummy`（非 NULL）。内核于是永远走缓冲分支：
  - 6 位数字生成逻辑是死代码；
  - 从 1 字节分配按 `idx*16` 越界读 16 字节，测的是隔壁内存的垃圾。
  修复：内核新增显式 `use_buf` 形参，不再依赖指针判空。
- **空密码被当成"未找到"**：`""` 是合法密码，但 `if not found:` 把它当假值。
  改为 `if found is None:`（crack_one / main / 汇总 / 导出询问共 4 处）。
- **GBK 控制台 / 输出重定时崩溃**：汇总行的 `✔`(U+2714) `✘`(U+2718) 在 cp936 下抛
  `UnicodeEncodeError`，脚本崩在打印汇总那一步，跑完根本看不到结论。
  新增 `_init_console()` 把 stdout/stderr 设为 `errors="replace"`。
- **"扫完未命中"后进度文件残留**：进度文件只在命中时被删，导致下次选"续扫"时
  剩余工作为 0，几秒就退出并报未找到。现在检测到这种情况会自动回退成完整重扫。
- **GPU 定长槽按字符数而非字节数打包**：密码超过 15 字节时，`bytearray` 切片赋值会
  撑长缓冲区，让同批后续所有槽位错位。新增 `pack_pw_slot()` 按实际字节数打包并截断。

### 新增

- `selftest_gpu.py`：用"密码已知"的合成 Agile 参数，20 秒内验证 GPU digits / 优先清单 /
  字典 / CPU 四条链路是否真的能命中。上面第一个 bug 它能一秒抓出来。

## [1.2.1] - 2026-09-27

- 兼容 CuPy 14：NVRTC 的 arch 参数从 `'sm_120'` 改为裸数字 `'120'`。
- cupy DLL 被 Windows 应用程序控制策略（智能应用控制 / WDAC）拦截时给出明确指引，
  不再误报为"未安装"并无效重装。
- cubin 磁盘缓存增加非空校验（历史上曾写入过 0 字节缓存，而 CuPy 模块加载是惰性的，
  坏文件要到 `get_function` 才炸）。
- 新增 SHA1 摘要 20 字节无法派生 >160 位 AES 密钥的显式回退检查（回退 CPU 而不是静默算错）。
- 修正 AES 解密末轮 ShiftRows 下标写法。

## [1.2] - 2026-09-27

- 断点续扫（`.bcrack.json`，5 秒一存）。
- 优先清单：高频弱口令 + 1930~2030 全部生日。
- 多文件 / 目录 / 通配符批处理。
- 命中后可选导出解密副本，并用 `msoffcrypto-tool` 交叉复核。
- PDF R6（AES-256）支持；ZIP 弱校验位命中后完整解密二次确认。

## [1.1] - 2026-09

- 加入 CUDA 内核（Agile：SHA-1/256/384/512 × AES-128/192/256 共 12 个入口）。
- 加入 `cryptography` 可选加速路径。

## [1.0] - 2026-09

- 首个版本：Office Agile / Standard / XOR、PDF R2-R4、ZIP ZipCrypto / WinZip AES。
- 纯标准库实现（自写 AES / SHA / RC4 / CFB 解析），无第三方依赖也能跑。

[1.2.2]: https://github.com/daoge96/doc-password-cracker/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/daoge96/doc-password-cracker/releases/tag/v1.2.1
