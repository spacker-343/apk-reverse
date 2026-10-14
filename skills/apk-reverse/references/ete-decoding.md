# ETE 解码：可复用的真实 native 指令区间验证

**何时加载本文：**已录到 socrates ETE AUX，但 dump 静默、只有 `NO_SYNC`，或要在另一个 APK 中复用已验证的 native 区间解码。source 缺失先读 `references/ete-socrates-module.md`；一般 ARM/ELF 分类见 `references/arm-tracing-elf-and-crash.md`。
When to load: ETE AUX decoding is silent/NO_SYNC, file-filter boundaries fail, or verified native ranges need reuse.

## 能力与限制

`observed`：在 socrates / SM8550、Android 13、精确内核基线上，root + SELinux Enforcing，设备原生 simpleperf `1.build.V14.0.18.0.TMKCNXM` 的 OpenCSD formatted 解码链路得到真实 native 指令区间。最初解码记录未刷内核；后续 perf 修复已仅持久刷入 `boot_a` 并通过正常重启验证，未改 APK、关闭 SELinux 或修改 syncfreq。

> 文件过滤的 VMA 边界误匹配已修复，零 AUX 的独立启停问题由 ete_record.py 修正；持久部署后 30ms/150ms 六次采集均有真实解码区间。仍有 reset/overflow 缺口，历史失败 trace 未恢复，不是无缺口完整执行路径或业务语义。

`runtime_trace_decoding_verified=true` **不等于** `full_trace_verified=true`。完整 branch-list、跨 CPU 全序、调用边恢复、OLLVM/VMP 或业务语义未验证。其他设备、内核、recorder、动态/JIT/匿名/被改写代码必须重新验证；不要改基线绕过关卡。

### 后续定位：内核修复与兼容 fallback

`observed`：自建 shell 的边界/内部范围对照复现了官方 perf 核心 VMA 端点误匹配：
代码起点恰好等于前一只读 VMA 的排他终点，原判断仍接受匹配，生成零长度比较范围，
首次匹配即返回。`0xb000` 起点无区间；移到 `0xb004` 后得到 1,001,990 个经过真实 maps/ELF
字节验证的区间，但有 overflow。这是内核核心逻辑，不是现有 ETE `.ko` 的构建逻辑改动。
修复片段、官方来源、点过滤语义与直接 C 回归在
`assets/ete/socrates-5.15.41/build/perf-fix/README.md`；构建/部署状态在
`assets/ete/socrates-5.15.41/evidence/perf-filter-repair.json`（部署前构建快照）。后续
`assets/ete/socrates-5.15.41/evidence/perf-filter-deployment.json` 记录两轮 RAM boot：第一轮边界比较器已修正，
两份失败 trace 实际零 AUX（不是未知 ID）；第二轮同一边界过滤已验证 433,583 个区间。
后续显式初始化重启/最终禁用的采集入口在三次 150ms、三次 30ms 中均成功采集并解码；之后仅持久刷入 `boot_a`，正常重启仍生效。持久部署后的另六次交替 150ms/30ms 采集均有 AUX 和验证区间，其中两次 ADB 中断解码在保留失败报告后用同一原 trace 重试成功。**仍有 overflow，原始历史小 trace 未恢复。**

未修内核且只需内部区间时，可用只读 fallback：

```powershell
python skills/apk-reverse/scripts/ete_addr_filter.py --maps work/ete/target.maps --manifest work/ete/manifests/target-manifest.json --elf-dir work/ete/elf --module libfoo.so --json
```

它按本次真实映射和哈希 ELF 生成 `--addr-filter` 参数，不执行采集、不修改内核。
可选 `--start-vaddr` / `--end-vaddr` 指定同一 executable PT_LOAD 内的 A64 对齐半开区间。
报告 `cropped_start_bytes` / `cropped_end_bytes` / `coverage_complete`；原生 simpleperf 的
排他 PT_LOAD 终点转换另有约束，不得称裁剪的指令已经追踪。
完整边界覆盖优先采用无硬件地址过滤的 `cs-etm:u`，解码后再限制目标模块，并检查 overflow。
APK 内映射、匿名/JIT/删除路径不适用此 fallback。采集前重新核对 maps，不复用旧 ASLR。

解码器源 ID 探测忽略 formatter 保留 ID（0 和 0x70..0x7f）；短流的 ID0 填充不再主导选择。
同一 CPU 探测范围发现多个真实源 ID 时拒绝，不以多数票忽略未知源。该探测不是全流完整性证明。

### 零 AUX 的采集器修复（socrates 已实测）

零 AUX 没有执行包，改 trace ID 不能恢复。`ete_decode.py` 返回 `no_aux_data`/rc1，不创建副本或连接设备。
`inferred`（根据 AOSP simpleperf/内核源码，未直接插桩 Xiaomi 二进制）：对已有线程，AUX 映射前启用事件可能使 `perf_aux_output_begin()` 先失败；短采集依赖后续调度/周期重启。退出时若只同步已发布缓冲区、不先禁用事件，又可能丢掉最终硬件数据。
`observed`：只做最终禁用仍有两次 30ms 零 AUX；修复入口在 `started` 后显式 `pause/resume` 并等待确认，计时结束先 `pause` 成功确认，再关闭 stdin，初始化重启与最终禁用共同干预后两组六次短窗口均成功。
此顺序让硬件停下并发布 AUX 后才排空/关闭读取线程；有效干预已经实测，不把源码推导冒充精确设备二进制内部测量。

```powershell
python skills/apk-reverse/scripts/ete_record.py --serial SERIAL --tid 1234 --duration 0.15 --addr-filter 'filter 0xb000-0x4a684@/system/bin/sh' --out-dir work/ete/new-capture
```

`SERIAL`/TID 必须来自本次目标设备/线程，输出目录必须为空；最多 60 秒，失败/超时不报成功，远端 watchdog 有界。
输出 `trace.perf`、本次 `maps.txt` 和 `record.json`；再用下述解码入口验证真实 ELF/maps。无需替换系统 simpleperf，
不自动加载模块、改 SELinux 或暂停/终止目标线程。命令中的文件边界需要已修 perf 内核；stock 仍需上述 fallback。
RAM boot 和持久部署后各三次 150ms/三次 30ms 全部非零 AUX 且有验证区间，是该实测配置的回归，不是所有负载或无缺口完整路径保证。
初始化确认前可能已有少量追踪，因此请求时长是确认后的有界活动窗口，不代表文件只覆盖该精确时间范围。

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
- I_ASYNC 候选不是 decoder 接受 packet/context 状态的证明。历史小过滤 trace 有 8,357 候选却只有 NO_SYNC；这是保留的旧失败，不能再泛称当前边界采集仍未修复。旧 FSCY/HSYCY 探针“窗口内没有同步包”的归因已撤回。
- 静默/无区间：先检查 AUX 字节数；零 AUX 返回 `no_aux_data`，不能靠改 ID 或同步参数恢复。非零 AUX 再查 metadata/流 ID、原生 dump 路径、packet/context、地址上下文与过滤/缺口，不直接归因为无同步或改 syncfreq。
- 有区间但 ADDR_NACC/映射错误：核对采集时 maps、ELF 哈希、PT_LOAD/file offset 与 EL0/EL1；不把 EL1 地址当 APK 执行验证。

## 脱敏历史证据与合成回归

`assets/ete/socrates-5.15.41/evidence/decode-result.json` 是聚合历史测量，不是新目标保证：

| 样本 | INSTR_RANGE 次数 / unique | 地址验证范围 | NO_SYNC 原因 |
|---|---:|---|---|
| native 目标 | 610,502 / 19,918 | 全部通过 maps/PT_LOAD/真实 ELF 字节 | reset 14,957；bad-packet 1,536；overflow 2,346 |
| 用户态 shell 对照 | 3,158,020 / 374 | sh 内 1,138,751 / 227；其他模块未请求验证 | reset 5；overflow 43,129 |
| 历史小过滤失败（原文件未恢复，非当前回归） | 0 / 0 | 不可用，harness rc 1（native rc 0） | reset 1,933；bad-packet 230 |

旧 `decode-result.json` / `decode-publication.json` 保留当时测量与当时限制文案，不代表当前修复状态；当前状态以 `perf-filter-deployment.json` 为准。旧 `runtime-result.json` / `runtime-summary.md` 只证明 source/AUX 采集，保持原样，不倒改为解码成功。GitHub 不携带真实目标 APK/ELF/maps/perf、完整 dump、设备序列号或主机用户路径；可复跑原输入留在本地项目。
本次运行生成的 manifest/decode.json 会记录本机绝对路径、设备序列号及环境，这是本地复跑证据，不是可直接发布的脱敏资产；外发前按 `references/desensitization-and-leak-scans.md` 另做白名单聚合与扫描。

安装目录也能独立运行合成回归（不连接设备，不需要真实目标）：

```powershell
python -m unittest discover -s skills/apk-reverse/assets/ete/socrates-5.15.41/decode -p test_ete_decode.py -v
```

29 项解码合成测试、10 项过滤规划及 6 项采集控制测试验证输入保护、未知布局拒绝、跨记录混合真实 ID 拒绝、真实同步/尾帧、A64/ELF 坐标、失败报告与清理；内核修复另有真实 C 函数回归。它们不替代新设备/新 APK 的实测能力关卡。固定 `.ko`/GPL 来源继续见模块文档。
