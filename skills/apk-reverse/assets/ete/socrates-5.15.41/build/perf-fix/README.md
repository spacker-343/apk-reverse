# perf 文件地址过滤：内核源码修复

## 状态和归属

这是 `kernel/events/core.c` 的修复，不是 `coresight-etm4x.ko` 的新版本。
已通过两轮 `fastboot boot` 临时启动验证，随后仅持久刷入 `boot_a` 并验证正常重启仍生效；其他备份分区未改，三个驱动 C 文件未改逻辑。
`observed`：官方 MiCode `socrates-t-oss` 提交
`3586ae7c7ea9eae1eb786600ece31907786480a2` 的 perf 核心允许 VMA 端点相碰就算匹配。
本轮下载检查的 Linux `linux-5.15.y`、`v6.6`、`master` 也保留该判断；这是继承的逻辑，不是模块构建改坏。
动态分支 URL 会变化，固定复现输入仍以 MiCode 提交及哈希为准。
随后取得 stock build ID 对应的 ACK 提交 `de2a4c25826bde1ec685714694511e6aeff35017`；
其完整 `core.c` 与上述 MiCode 文件 SHA-256 相同，生成器同样接受，不靠版本字符串猜兼容。

源文件：<https://github.com/MiCode/Xiaomi_Kernel_OpenSource/blob/3586ae7c7ea9eae1eb786600ece31907786480a2/kernel/events/core.c>

## 已复现的因果链

文件偏移前一个只读 VMA 是 `[0, 0xb000)`，代码 VMA 从 `0xb000` 开始。
原 `perf_addr_filter_match()` 使用 `>` / `<`，接受只有端点相碰的范围。
`perf_addr_filter_vma_adjust()` 得到前一个 VMA 的零长度范围；
`perf_addr_filter_apply()` 首次匹配就返回，错过代码 VMA。
在同一 shell/CPU/采集窗口的控制中，`0xb000` 起点产生零长度比较范围和零指令区间；
移到 `0xb004` 后得到正确比较范围和 1,001,990 个经过 maps/ELF 字节验证的区间。
这些控制存在 overflow，不能证明完整执行路径，也不能恢复历史 trace 中缺失的指令。

## 修复内容

`perf_addr_filter_match.c` 只替换匹配函数；VMA 地址转换、锁、返回路径、驱动不变。

- 非空区间采用半开区间的真实重叠语义，排除双方端点相碰。
- 零长度 start/stop 是一个地址点：VMA 起点/内部可匹配，排他终点不匹配。
  解析器本就禁止零长度 `filter`，不能简单把两个比较符号都改成非严格比较。
- 用差值而非 exclusive end 相加，避免 unsigned long 加法溢出。
- 仍核对文件 inode；没有把所有代码映射或所有文件无条件纳入采集。

## 生成独立源码副本

输入只读，输出必须不存在。生成器只接受固定官方源码 SHA-256：
`19999bbbf7b9b651e84d33a044c292527c775d38a3659b8b888afeef80ab17b9`。

```sh
python3 apply_perf_fix.py --source ORIGINAL/kernel/events/core.c --output BUILD_COPY/kernel/events/core.c
python3 test_perf_fix.py --source ORIGINAL/kernel/events/core.c --work-dir SCRATCH/perf-c-regression
```

这些命令从本目录运行；`ORIGINAL`、`BUILD_COPY`、`SCRATCH` 是本次实际路径。
先在独立、未占用的源码副本准备输出位置；生成器不原地改源码、不安装模块、不连接手机。
没有 force 开关；不同源版本必须重新核对匹配/点过滤语义。

## 已做与未做的验证

`observed`：LP64 Linux 宿主 C 编译了真实原函数、修复函数和未改动的 VMA 转换函数，
12 个具名用例、50,000 组固定种子随机比较、文件身份拒绝和首个 VMA 匹配均通过。
首个映射从错误的 `[index=0, size=0]` 变成正确的 `[index=1, size=0x3f684]`；
内部范围行为保持一致，边界 start/stop 点正确落入后一个映射。

`observed`：完整精确 ACK 源码的正式 Kbuild 已编译修复后的 AArch64 `kernel/events/core.o`，
保留 full LTO、CFI、PAC/BTI 与符号裁剪。输出是 1,722,772 字节 LLVM bitcode，
SHA-256 `9d13b88bfcad998e0669f21b14f65877d7173fd17c6f0a43a41b6be43c8079c5`。
公开 GKI 列表合并生成真实符号白名单，未造空头文件；其历史 stock 生成文件身份仍未证明。
配置同步有宿主能力检测差异，详见证据；该对象不证明整内核/vendor 模块 ABI 兼容。

`observed`：恢复大小写后，工作副本的 73,852 个普通文件逐一与精确 ACK 归档比对，
只有上述 `core.c` 修复不同。Windows/WSL 构建必须让源码、完整输出树及临时目录区分大小写；
归档中有 13 组、26 个仅大小写不同的文件。修复源码目录但遗漏输出目录，仍会使
UAPI `ipt_ECN.h.tmp` 与 `ipt_ecn.h.tmp` 并行撞名。保留备份、重建大小写敏感输出树后，
须清理并重新生成旧头文件与 kheaders；不要关闭相关配置掩盖宿主文件系统问题。

宿主 full LTO 在默认 WSL 16 GB/4 GB swap 下被 OOM 杀死；经授权提高到 24 GB/8 GB 后
完成 LTO/MODPOST/最终链接。pahole v1.25 的 ENUM64 输出与这版 5.15 BTF 解析器不兼容；
宿主包装器传入 `--skip_encoding_btf_enum64`，保持 BTF 开启，临时 ELF 的生成与原解析器读取
控制均通过。最终 Image 正式构建通过 BTFIDS/SORTTAB/SYSMAP；7,029 项导出 CRC、导出类型
和直接从 stock 原始 ELF 恢复的命名空间全部匹配，零缺失/额外/冲突。
Image：49,572,352 字节，SHA-256
`43306d8330674e5a66da1102ab5f08257709e4ed991a4e709a7b56811b785f33`。
保留 full LTO、CFI、BTF、PAC/BTI 和符号裁剪；静态验证仍不证明完整 vendor ABI。

**宿主 C 回归不是设备端完整修复证明。** `../../evidence/perf-filter-repair.json` 保留部署前构建快照；
后续临时启动结果见 `../../evidence/perf-filter-deployment.json`。
现有 `.ko` 字节不变；将本函数放进驱动 `.ko` 不会替换 perf 核心。

## 仍需分层处理

- 原生 simpleperf `VaddrToOff()` 拒绝 executable PT_LOAD 的排他终点，是另一个用户态问题；
  修复 perf 核心不等于该端点转换已修复。
- formatter ID0 填充不是真实源；解码器独立排除保留 ID 并拒绝混合真实源布局。
- `scripts/ete_addr_filter.py` 是未修内核的兼容 fallback，明确报告边界裁剪，非根治方案。
- 零 AUX 属于独立的 recorder 启停时序问题；已加入显式初始化重启/最终禁用的采集入口，历史小 trace 未恢复。

## 临时启动验证（后续记录）

`observed`：bootloader 接受未签名 RAM boot，Android 完成开机；运行 BTF 与本地 `vmlinux` 逐字节相同。
root/SELinux Enforcing 保留，原 ETE 模块恢复八源。两次 CPU4、0.15 秒、正反顺序对照中，
`0xb000` 边界比较器均变为正确非零范围；内部样本分别有 437,857 / 440,138 个 maps/ELF 验证区间。
第一轮两份边界样本实际为 **零 AUX**，旧 formatted-layout 错误归类已修正为 `no_aux_data`。
第二轮同一边界过滤已验证 433,583 个真实区间；内核边界修复有执行证据，不再只是比较器正确。

原厂 split BTF 校验失败和 PMIC/device-link WARN 在原内核恢复启动中也出现，253 个失败模块集合及
7 个 WARN 位置/次数相同；“新构建引入这些日志”的归因已被对照推翻，不据此关闭 BTF。
第一轮正常重启恢复原内核、五个备份分区哈希不变，第二轮 RAM boot 再次成功；后续经授权仅持久刷入 `boot_a`。
`inferred`（AOSP simpleperf/内核源码推导，未直接插桩 Xiaomi 二进制）：已有 TID 在 AUX 映射前启用事件可能先失败，随后依赖调度切换/周期重启；退出读取/事件关闭顺序可能遗漏最终硬件数据。
`scripts/ete_record.py` 在 `started` 后等待 `pause/resume` 确认，再开始有界计时；结束先 `pause` 确认再关闭 stdin。
只修最终禁用时，30ms 仍有两次零 AUX；加初始化重启后，交替三次 150ms/三次 30ms 全部采集及解码成功，
每份 maps/ELF 验证通过，原 trace 不变，远端清理成功。它不替换系统 simpleperf，不自动加载模块，不停止用户线程。
完整路径仍未验证：这些样本有 overflow；历史失败 trace、simpleperf 排他终点转换和长期 vendor 健康仍分别受限。
后续聚合证据见 `evidence/perf-filter-deployment.json`，原始采集和详细报告仅留本地。

## 持久部署验证

`observed`：只写 `boot_a`，刷后开机及再次正常重启都运行同一修复内核；完整 boot_a 分区哈希与候选镜像相同，
运行 BTF 与构建产物相同；boot_b/init_boot_a/vendor_boot_a/vbmeta_a 四个备份分区哈希不变，槽位 a、root、Enforcing 保留。
原 ETE `.ko` 重启后显式加载，未配置 autoload 或持续追踪。普通重启现在不会返回 stock；回滚必须在 bootloader 恢复原 boot_a。
原镜像、完整回滚操作和持久部署原始记录只留本地；发布聚合见 `evidence/perf-filter-deployment.json`。
持久部署后又执行三对交替 150ms/30ms 边界采集，六次均非零 AUX，并用采集时 maps/哈希 ELF 验证真实区间；两次 ADB 中断解码保留失败报告，同一原 trace 重试成功。最终只读核验确认原 `.ko` 已加载、八源空闲、实验暂存目录清理完成。仍有 overflow，不宣称完整执行路径。
