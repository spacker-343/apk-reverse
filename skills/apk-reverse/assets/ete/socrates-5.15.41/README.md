# K60 Pro：可重新加载的 ETE source 模块

此目录是工作区 `ete-assets/socrates-5.15.41-2026-10-13` 的精选发布副本；原归档保持不变。
`.ko` 随 skill 保存，避免安装 skill 后只剩启用教程而没有重启恢复所需的文件。

## 适用范围

仅验证于 Redmi K60 Pro / socrates / SM8550，Android 13 V14.0.18.0.TMKCNXM，完整内核
`5.15.41-android13-8-00015-gde2a4c25826b-ab9439604`，root 可用，SELinux Enforcing。
这不是通用 K60 Pro 驱动，也不是 Magisk 安装 ZIP。系统、配置、stock CoreSight ABI 改变后，
即使 `uname -r` 相同也应重新核验 CRC/CFI/结构；版本字符串检查不是 ABI 兼容证明。

- 模块：`module/coresight-etm4x.ko`，1,647,368 字节。
- SHA-256：`285f8be46dbba1003d5b2d1c0bfb32c7d4dcbc81397145c428adf4ded1960fb4`。
- 依赖：stock `coresight`，保留 CFI/MODVERSIONS；未签名，没有 BTF。
- 来源与固定构建输入见 `provenance.json`；静态检查见 `abi/exact-module-verification.json`。
- 运行证据见 `evidence/runtime-summary.md`，它是脱敏摘要，不是本次重新运行的记录。
- `SHA256SUMS.txt` 覆盖发布文件；原始 `.ko` 未重新编译、剥离或改字节。
- `.ko` 保留原构建 DWARF 路径（含构建主机用户名），以保持实测字节与哈希；没有剥离或重编译冒充原模块。
- `check_repo.py` 仅对这条模块路径及其固定 SHA-256 作公开 DWARF 例外，并打印说明；任意改动不再排除。显式运行扫描器仍可检查模块。
- 本次发布复测见 `evidence/publish-check.json`：新工具成功采集并清理；没有重新加载、重启或配置 autoload。

## 重启恢复

从仓库根目录运行（安装 skill 后使用相应 scripts 路径）：

```powershell
# 主机核验，不访问手机
python skills/apk-reverse/scripts/ete_module.py --verify-only
# 只读设备基线与八个 source 状态
python skills/apk-reverse/scripts/ete_module.py
# 重启后明确请求加载；只在基线、主机/设备哈希匹配时 insmod
python skills/apk-reverse/scripts/ete_module.py --load
# ADB 不在 PATH 时使用 --adb；多设备时使用 --serial
```

加载采用 `boot_enable=0 pm_save_enable=1`。`boot_enable=0` 不在初始化时启动采集；
这份驱动的 `pm_save_enable=1` 表示 **never**，不是“启用省电/状态保存”。
工具不修改 SELinux、不刷分区、不 force-load、不安装开机脚本、不启动 trace。
已 Live 时只核对状态，不重复加载或自动卸载。若 source 为 1，报告正在使用，不把它写成空闲。
加载报错时查看 dmesg；不要照抄旧实验结论而改 Permissive 或强行 insmod。

**提交 GitHub 不等于开机自动启用。** 当前模块只在本次启动中存在；重启后可用上述 `--load` 恢复。
如另行需要开机加载，必须单独设计、审核和重启验证；本发布没有声称完成这一功能。

## 按需追踪

```powershell
python skills/apk-reverse/scripts/device_hw_probe.py --expect-root --json
python skills/apk-reverse/scripts/device_hw_probe.py --expect-root --smoke-test --duration 1 --json
```

旧采集流程见 `references/ete-socrates-module.md`；新解码入口、maps/PT_LOAD/ELF 验证和复用步骤见 `references/ete-decoding.md`（均相对 skill 根目录）。
后续真实 native 区间已验证，但完整路径、OLLVM/VMP 还原、睡眠唤醒与长时稳定性未验证。
小过滤样本仍只有 NO_SYNC，具体原因未闭合；成功样本也存在 reset/overflow 缺口。因此当前验证的是真实指令区间，不是无缺口完整执行路径或业务语义。

## 构建材料与不上传的内容

保留官方三个驱动 C 文件、外部 Makefile、最终配置差异与 stock `Module.symvers`。
源码是上游 GPL-2.0 驱动；版权和 SPDX 头原样保留，二进制对应同一 GPL-2.0 源码。
没有把约 780 MB 的官方源码/Clang 压缩包、stock 内核镜像、原始手机日志或 trace 上传 Git。
固定下载地址、输入哈希及构建注意事项见 `provenance.json` 和 `build/README.md`。

## 解码资产

- `decode/`：设备 OpenCSD harness、deframe/trace-ID/ELF 坐标依赖、独立合成 fixture 与 23 项测试。
- `evidence/decode-result.json`：脱敏聚合历史测量；不携带真实目标 APK/ELF/maps/perf 或完整 dump。
- `evidence/decode-publication.json`：本次资产范围与输入保护说明；旧 runtime/publish-check 记录不倒改。
- skill 的三个 `scripts/ete_*.py` 新入口转发到同一 backend，安装后无需原项目。
  Python 3.9+、ADB 和精确 root 设备；Capstone 仅为可选助记符依赖。

`SHA256SUMS.txt` 覆盖发布资产（自身除外），固定 `.ko` 字节与 GPL 来源保持不变。
