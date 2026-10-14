# K60 Pro ETE：实测 source 模块、重启恢复与采集边界

**何时加载本文：**socrates 上 `cs_etm` 已存在但报 `etm devices are not available`，
曾成功追踪但重启后八个 ETE source 消失，或需要找随 skill 发布的模块与证据。
一般 ARM/ELF/OLLVM/VMP 分类仍由 `arm-tracing-elf-and-crash.md` 负责。

## 已观察到什么

`observed`（随附原资产记录）：在 Redmi K60 Pro / socrates / SM8550，Android 13
V14.0.18.0.TMKCNXM、内核 `5.15.41-android13-8-00015-gde2a4c25826b-ab9439604` 上，
root 临时加载官方 ETM4x source 模块后，CPU0–CPU7 八个 ETE v1.0 source 注册、绑定成功。
SELinux 始终 Enforcing，没有刷 boot/vendor_boot/vendor_dlkm，没有配置开机自动加载。

短时用户态录制返回 0，产生 2,166,016 字节 AUX 数据、2,433,042 字节记录文件，
`simpleperf dump` 识别 cs-etm:u、auxtrace_info 和 AUXTRACE；结束后八个 source 的 enable_source=0。
这份旧记录是 **硬件采集 + 文件结构验证**，不是完整 ETE 指令/分支路径解码，也不是真实 APK 还原。
后续独立解码记录已验证真实 native 指令区间，工具和复用步骤见 `references/ete-decoding.md`；不倒改旧样本结论。

`unverified`：无缺口完整路径、长时/睡眠唤醒、内核态、跨 CPU 全序，以及 OLLVM/VMP 语义恢复。
`observed`（后续修复）：perf 文件过滤的 VMA 边界误匹配已修复，独立零 AUX 启停问题由 `ete_record.py` 修正；仅持久刷入 `boot_a` 后正常重启仍有效，30ms/150ms 六次采集均有真实 maps/ELF 验证区间。仍有 reset/overflow 缺口，历史失败 trace 未恢复；详见 `references/ete-decoding.md` 与 `assets/ete/socrates-5.15.41/evidence/perf-filter-deployment.json`。
禁止把这条局部成功推广为所有 K60 Pro/所有内核/新目标；新目标必须重采 maps/真实 ELF 并验证。

## 随 skill 携带的资产

目录：`assets/ete/socrates-5.15.41/`（相对 skill 根目录）。

- `module/coresight-etm4x.ko`：实际成功模块，1,647,368 字节；
  SHA-256 `285f8be46dbba1003d5b2d1c0bfb32c7d4dcbc81397145c428adf4ded1960fb4`。
- `manifest.json`：精确设备/内核/哈希/参数，不是通用兼容清单。
- `provenance.json`：固定 MiCode 提交、Clang 14.0.7 URL 与输入哈希。
- `abi/Module.symvers`、`abi/exact-module-verification.json`：stock 导出 CRC 与静态结果。
- `build/driver`、`build.config`、`exact-config-diff.txt`：官方驱动和实际构建输入。
- `evidence/runtime-summary.md`、`runtime-result.json`：脱敏记录，保留成功和未验证项。
- `SHA256SUMS.txt`：发布副本的校验清单；原工作区归档保持不变。

不上传约 780 MB 的上游原包、stock 内核镜像、原始系统日志和原始 trace；
这些不是重启恢复必需文件，且包含环境信息。固定上游地址和构建过程仍可审阅。
本模块使用上游 GPL-2.0，驱动版权/SPDX 与 COPYING 保留，不受仓库其他代码许可证替代。

## 重启后的恢复步骤

从仓库根目录运行；安装副本使用其实际 scripts 路径：

```powershell
python skills/apk-reverse/scripts/ete_module.py --verify-only
python skills/apk-reverse/scripts/ete_module.py --json
python skills/apk-reverse/scripts/ete_module.py --load --json
python skills/apk-reverse/scripts/device_hw_probe.py --expect-root --json
```

默认是只读；`--verify-only` 不连接手机；**只有 `--load` 会写设备**：
核对基线、root、Enforcing、依赖、主机模块哈希 → adb push 到 `/data/local/tmp` →
设备端 SHA-256 → chmod 600 → 再核对状态 → insmod → 核对 Live、参数与八个 source/绑定。
多设备指定 `--serial`，ADB 不在 PATH 指定 `--adb` 或 `ADB` 环境变量。

已加载时只检查，不重复 insmod、不自动 rmmod。加载只恢复“驱动待用”，不打开 source。
同型号但内核/系统更新，或改过 stock CoreSight/配置，必须重新验证 ABI，不能改 manifest 绕过门槛。

**上传模块 != 开机自动加载。** `.ko` 文件存在不会自动 insmod；本工具不安装 Magisk service.d。
本次启动里驱动 Live、所有 enable_source=0 是推荐空闲状态；重启后再次执行显式 `--load`。
不要把持久保存文件、内核 Live、持续追踪这三个状态混为一谈。

### 为什么不会显示在 Magisk 模块管理

Linux 内核模块 `.ko` 由 `insmod` 加入本次启动的内核内存；Magisk 模块则是 `/data/adb/modules/<模块ID>/` 下含 `module.prop` 的安装包。Magisk 页面不会枚举内核已加载的 `.ko`，直接加载驱动不会生成模块条目。
可以另行制作带设备/内核/哈希/依赖检查的 Magisk 自动加载包：开机仅加载驱动并核验八个 source，保持 `boot_enable=0` 和 source 空闲，不自动追踪、不强制加载、不改 SELinux。安装可见不等于驱动加载成功，仍需核验运行状态；禁用通常在下次启动阻止自动加载，不等于立即卸载。
当前未安装这种包。持久刷入的 perf 核心修复并未把外置 `.ko` 编入内核；已验证重启后显式恢复驱动，开机自动加载包本身仍未制作或验证。

## 已执行过的采集命令

以下是原记录中的设备 root shell 命令，输出路径必须没有待保留结果：

```sh
simpleperf record -e cs-etm:u --aux-buffer-size 1048576 \
  --no-dump-symbols --no-dump-kernel-symbols \
  -o /data/local/tmp/ete-exact-smoke.data -- /system/bin/ls /system/bin
simpleperf dump -i /data/local/tmp/ete-exact-smoke.data
```

自动短测试可用 `scripts/device_hw_probe.py --expect-root --smoke-test --duration 1`，
其临时文件名唯一，结束会清理并报告清理结果。输出数据/结构成功不报告完整解码成功。
`cs-etm:u` 是 simpleperf 用户态事件形式；不要使用之前失败的 `cs-etm//u`。

正式目标采集需要保留 ELF/Build ID、maps、执行时代码镜像、线程/CPU、触发输入、
采集命令、工具版本与丢包信息。`--no-dump-symbols` 仅用于小范围 smoke，不能替代符号归档。
使用 `scripts/ete_decode.py` 的设备原生 OpenCSD 路线，见 `references/ete-decoding.md`；先做用户态对照，再以 maps/PT_LOAD/真实 ELF 字节验证目标区间。
Stalker 日志解析器不是 perf AUX 解码器，不能把原始 AUX 直接交给 `stalker_report.py`。

## 失败分流与恢复

- 八个 source 不存在：先核对驱动是否加载、设备树/绑定；funnel 或 cs_etm 存在不足以证明 source 存在。
- Unknown symbol/CRC/CFI/Oops：停止加载，检查 ABI 与构建；不要强制加载或循环重试。
- EPERM：先记录 root capability、modules_disabled、具体 dmesg；旧失败同时修正了源码、Clang、CRC、MMIO，
  唯一根因未确认，不能归因成“只需关 SELinux”。本成功发生于 Enforcing。
- `boot_enable=0` 禁止初始化自动追踪；本驱动 `pm_save_enable=1` 为 never，非省电开关。
- 正常结束 simpleperf 后检查 source 回到 0；别手动全写 1 绕过 perf 的 sink/AUX 管理。
- 如需卸载，先停止追踪，再普通 `rmmod coresight_etm4x`；原记录未实测卸载路径。
  不强制卸载。未配置 autoload 的正常重启会清除临时模块；后续已实测正常重启并显式重新加载，未安装开机加载包。

## 构建为何可加载

固定 socrates-t-oss 提交配合精确 Android Clang/LLD 14.0.7，stock Image 与 coresight
提供 7,063 项 CRC；58 个导入和 59 个版本项零缺失/冲突，模块结构 960 字节与 stock 相同，CFI 保留。
唯一驱动编译开关 `__DISABLE_TRACE_MMIO__` 去除四个未导出的可选日志引用，未改三个 C 文件逻辑。
CRLF 的 Module.symvers 曾导致 modpost namespace 错误，改为 LF 后通过。
缺 OF 自动加载 alias 不代表没有运行时 ETE 匹配表；实际 insmod 已绑定八个 source。
未签名、缺 BTF 没阻止这次短时采集，但不推出别的内核也会接受。
