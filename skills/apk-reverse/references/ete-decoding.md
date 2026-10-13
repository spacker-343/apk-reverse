# ETE 解码：可复用的真实 native 指令区间验证

**何时加载本文：**已录到 socrates ETE AUX，但 dump 静默、只有 `NO_SYNC`，或要在另一个 APK 中复用已验证的 native 区间解码。source 缺失先读 `references/ete-socrates-module.md`；一般 ARM/ELF 分类见 `references/arm-tracing-elf-and-crash.md`。

## 能力与限制

`observed`：在 socrates / SM8550、Android 13、内核 `5.15.41-android13-8-00015-gde2a4c25826b-ab9439604`，root + SELinux Enforcing，设备原生 simpleperf `1.build.V14.0.18.0.TMKCNXM` 的 OpenCSD formatted 解码链路得到真实 native 指令区间。没有改 APK、刷内核、关闭 SELinux 或修改 syncfreq。

> 小过滤样本仍只有 NO_SYNC，具体原因未闭合；成功样本也存在 reset/overflow 缺口。因此当前验证的是真实指令区间，不是无缺口完整执行路径或业务语义。

`runtime_trace_decoding_verified=true` **不等于** `full_trace_verified=true`。完整 branch-list、跨 CPU 全序、调用边恢复、OLLVM/VMP 或业务语义未验证。其他设备、内核、recorder、动态/JIT/匿名/被改写代码必须重新验证；不要改基线绕过关卡。

## 安装独立资产与依赖

安装 skill 自带 `scripts/ete_decode.py`、`scripts/ete_target_manifest.py`、`scripts/ete_addr_space.py`。它们转发到同一份 `assets/ete/socrates-5.15.41/decode/` backend，不依赖旧项目工作区或真实样本。backend 的 deframe/trace-ID 模块是诊断依赖；正式入口必须用有界 `ete_decode.py`，不要用底层自由改 ID 的 CLI 绕过未知布局拒绝。

- 主机 Python 3.9+；manifest、ELF/PT_LOAD 和 dump 统计使用标准库。Capstone 可选，仅用于末指令助记符；缺失不影响 ELF 字节检查。
- ADB、在线设备、root；设备需有 `timeout` 和支持 `--dump-etm element` 的原生 simpleperf/OpenCSD。主机不要求 C++ 工具链。
- `device_hw_trace` 的 root optional 只表示只读 probe 可非 root；实际解码和模块加载需要 root/精确环境。先跑 probe 和模块状态门槛，不能凭一个 sysfs 节点宣布可用。

以下命令从仓库根目录运行；已安装时把 `skills/apk-reverse/scripts` 换为安装 skill 的实际 `scripts` 路径，其他输入/输出放本次目标工作目录，不放 skill 内。

```powershell
python skills/apk-reverse/scripts/ete_module.py --verify-only
python skills/apk-reverse/scripts/ete_module.py --json
python skills/apk-reverse/scripts/device_hw_probe.py --expect-root --json
python skills/apk-reverse/scripts/ete_decode.py --help
```

source 不存在且精确模块/环境核对通过时，才显式执行 `ete_module.py --load --json`。不自动加载、不修改 source/syncfreq、不配置开机脚本。

## 新目标复用流程

1. **采集前记录基线。**保存设备/内核、root/Enforcing、八个 source、simpleperf 版本/哈希。明确目标 PID/TID、线程/CPU、触发输入、时间窗口、用户态过滤及 buffer。先用 `/system/bin/sh -c 'while :; do :; done'` 做有界用户态对照；采集时保存其 maps、exe 和真实设备 `sh` ELF，结束停止自建进程。
2. **采集目标并留证。**在设备 root shell 使用 `cs-etm:u`，例如 `simpleperf record -e cs-etm:u --aux-buffer-size 1048576 -p PID --duration 1 -o /data/local/tmp/target.perf`；PID 和输出路径需替换为本次值，拒绝覆盖旧结果。保存采集时 `/proc/PID/maps`、exe、命令/日志、相关 ELF/Build ID 与 SHA-256，pull 后保存原 trace 哈希。不要把采集前后不同 ASLR/版本的 maps 混用；APK 内直接映射、提取文件、运行时镜像必须明确坐标/身份。
3. **建立真实 ELF manifest。**manifest 工具只读 APK/ELF，产出 ELF 身份和 PT_LOAD。单 ELF 示例：

```powershell
python skills/apk-reverse/scripts/ete_target_manifest.py --elf work/ete/elf/libfoo.so --out-dir work/ete/manifests --json
```

也可使用 `--apk work/target.apk --entry lib/arm64-v8a/libfoo.so --out-dir work/ete/manifests --json`；对多个模块可重复 `--entry`。单 ELF 模式只写 manifest，不复制 ELF，下面的 `--elf-dir work/ete/elf` 指向原 ELF 目录；APK 提取模式则使用 `--elf-dir work/ete/manifests`。已脱壳/改写代码不能冒充原 APK 字节；工具拒绝未能落到正确文件坐标的地址。

4. **解码副本并验证区间。**输出目录必须不存在，timeout 为 1–300 秒；显式指定每个需要验证的模块。

```powershell
python skills/apk-reverse/scripts/ete_decode.py --trace work/ete/target.perf --out-dir work/ete/decoded --serial DEVICE_SERIAL --timeout 120 --maps work/ete/target.maps --manifest work/ete/manifests/target-manifest.json --elf-dir work/ete/elf --module libfoo.so
```

ADB 不在 PATH 时加 `--adb path/to/adb.exe`。多个模块重复 `--module`。工具只允许已观测的八源 ETE/perf 布局；当 metadata ID 为 `0x10+2*cpu` 而 formatted stream 为 `cpu+1` 时，只改新副本的八个 ID 槽位；已对齐保持不变，未知布局拒绝猜测。原 trace/AUX 不改，记录 source/fixed 哈希和 source_unchanged。

设备解码命令为 UUID 临时目录中的 `timeout N simpleperf --log error dump -i trace.perf --dump-etm element`，通过 `adb shell -T` 保存 stdout/stderr，主机也有超时，finally 清理远端目录。输出 `id-aligned.perf`、`elements.txt`、`decoder.stderr.txt`、`decode.json`；dump 可非常大，先检查磁盘空间，流式统计，不整体载入聊天上下文。

5. **读报告而不是只看 rc。**rc 0=有 INSTR_RANGE；rc 1=无区间；rc 2=不可用或远端清理失败。rc 0 本身不保证地址验证通过，更不保证无缺口。逐项核对 `instruction_ranges`、`unique_ranges`、`mapped_range_occurrences`、`unique_ranges_in_requested_modules`、`module_errors_unique`、`a64_size_mismatches_unique`、`element_counts`、`no_sync_reasons`、stderr、source_unchanged 和 remote_cleanup。未请求的模块不算已验证；requested module 的区间必须完整位于采集时同一 maps row、可执行 PT_LOAD 的文件范围，并通过两式坐标、ELF 身份哈希和完整字节读取。

可用单地址诊断定位映射失败，不启用 `--allow-hash-mismatch` 冒充验证：

```powershell
python skills/apk-reverse/scripts/ete_addr_space.py --manifest work/ete/manifests/target-manifest.json --maps work/ete/target.maps --elf-dir work/ete/elf --module libfoo.so --address 0x7000001000 --json
```

该地址仅为格式示例，必须换成本次 dump 的真实地址。Capstone 末指令助记符以地址 0 解出，branch immediate 不是 runtime target。

6. **闭环与清理。**保留完整原始输入和本地报告，结束停止自建 workload、检查八个 enable_source=0、清理本轮远端临时目录，保持 Enforcing。不跨 reset/overflow/bad-packet/ADDR_NACC 拼接为执行边。相同假设失败两次后重新分类，不以 rc 0、非空 dump 或 I_ASYNC 候选替代成功证明。

## 同步判据与失败分流

- OpenCSD `iPktASync()` 的 I_ASYNC 判据是 **11 个 `00` + `80`**；来源：<https://github.com/Linaro/OpenCSD/blob/master/decoder/source/etmv4/trc_pkt_proc_etmv4i.cpp>。ETE 复用该处理器。扫描按 AUX record/source 独立解帧，记录不足一帧尾字节，不跨 record 拼接。
- I_ASYNC 候选不是 decoder 接受 packet/context 状态的证明。旧 FSCY/HSYCY 探针“窗口内没有同步包”的归因已撤回；小过滤样本也有 8,357 候选，但仍只有 NO_SYNC。
- 静默/无区间：先看 metadata/流 ID、原生 dump 路径、packet/context、地址上下文，再看过滤/缺口；不要直接归因为无同步或去改 syncfreq。
- 有区间但 ADDR_NACC/映射错误：核对采集时 maps、ELF 哈希、PT_LOAD/file offset 与 EL0/EL1；不把 EL1 地址当 APK 执行验证。

## 脱敏历史证据与合成回归

`assets/ete/socrates-5.15.41/evidence/decode-result.json` 是聚合历史测量，不是新目标保证：

| 样本 | INSTR_RANGE 次数 / unique | 地址验证范围 | NO_SYNC 原因 |
|---|---:|---|---|
| native 目标 | 610,502 / 19,918 | 全部通过 maps/PT_LOAD/真实 ELF 字节 | reset 14,957；bad-packet 1,536；overflow 2,346 |
| 用户态 shell 对照 | 3,158,020 / 374 | sh 内 1,138,751 / 227；其他模块未请求验证 | reset 5；overflow 43,129 |
| 小过滤样本 | 0 / 0 | 不可用，harness rc 1（native rc 0） | reset 1,933；bad-packet 230 |

旧 `runtime-result.json` / `runtime-summary.md` 只证明 source/AUX 采集，保持原样，不倒改为解码成功。GitHub 不携带真实目标 APK/ELF/maps/perf、完整 dump、设备序列号或主机用户路径；可复跑原输入留在本地项目。
本次运行生成的 manifest/decode.json 会记录本机绝对路径、设备序列号及环境，这是本地复跑证据，不是可直接发布的脱敏资产；外发前按 `references/desensitization-and-leak-scans.md` 另做白名单聚合与扫描。

安装目录也能独立运行合成回归（不连接设备，不需要真实目标）：

```powershell
python -m unittest discover -s skills/apk-reverse/assets/ete/socrates-5.15.41/decode -p test_ete_decode.py -v
```

23 项合成测试验证输入保护、未知布局拒绝、真实同步/尾帧、A64/ELF 坐标、失败报告与清理，不替代新设备/新 APK 的实测能力关卡。固定 `.ko`/GPL 来源继续见模块文档；本次只固化解码工具、证据和限制。
