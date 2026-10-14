# ARM 硬件追踪、ELF 地址与 native 还原

**什么时候读这篇：**你看到的是 arm64 的 PIE 可执行文件、`.so` 共享库、native 崩溃、OLLVM 控制流平坦化、native VMP 解释器，或者有人说“手机支持 ETE/SPE/BRBE，所以可以直接脱壳”。这篇把这些词拆开，给出一条不会把“接口存在”误报成“能力可用”的路线。

**Load this when:** ARM tracing names, ELF/crash addresses, or OLLVM/VMP path evidence decide the next route.

> **强度说明：**分为 `observed`、`inferred`、`unverified`。socrates 精确内核上的八核 ETE 初始化、短时 AUX 采集及 maps/PT_LOAD/真实 ELF 字节验证的 native 指令区间已有 `observed` 记录，见 `references/ete-socrates-module.md` 与 `references/ete-decoding.md`。后续 perf 边界过滤及独立零 AUX 启停问题已修复，持久部署后 30ms/150ms 六次采集均有验证区间；仍有 reset/overflow 缺口，历史失败 trace 未恢复，不是完整执行路径或业务语义。运行 `scripts/device_hw_probe.py` 保存本次输出，其他设备/内核/新目标必须重新验证。

## 1. 先建立一张“能力分层图”

这一节解决最常见的误判：看到一个目录或一个事件名，就宣布“硬件追踪可用”。

把能力拆成四层：

```text
硬件线索
  ↓
内核接口
  ↓
录制器事件
  ↓
真实 trace 文件 + 解码
```

| 层 | 你要看到什么 | 能否单独证明 ETE 可用 |
|---|---|---|
| 硬件线索 | SoC/CPU 可能实现 ETM/ETE，CoreSight 节点出现 | 不能 |
| 内核接口 | `cs_etm`、CoreSight source/sink 节点被内核暴露 | 不能 |
| 录制器事件 | `simpleperf list` 列出 `cs-etm` | 不能 |
| 真实采集 | `simpleperf record -e cs-etm` 成功，生成可读 `perf.data` | 仍需解码验证 |
| 解码闭环 | 用 ELF 和映射信息把 trace 还原成正确地址/分支 | 才能把它用于分析 |

💡 **Go 类比：**CPU 像硬件实现，内核像接口适配层，`simpleperf` 像客户端 SDK，OpenCSD 等解码器像协议解析器。一个 Go 服务“有 `/trace` 路由”不代表后端真的连接了数据库；同理，`cs-etm` 出现在列表里不代表 trace source 已经能产生数据。

运行只读探测：

```bash
python skills/apk-reverse/scripts/device_hw_probe.py --json
```

如果要做短时间烟雾测试，必须显式打开：

```bash
python skills/apk-reverse/scripts/device_hw_probe.py --smoke-test --duration 1
```

`--smoke-test` 会在设备的 `/data/local/tmp` 创建一个短时文件并在结束后删除。它不是补丁，也不是绕过检测；但它确实会启动一次 perf 采集，所以目标设备应当处于可丢弃的研究状态。

**判定规则：**

- `interface_visible_but_not_recorded`：有线索或接口，但不能录制；不要称为“ETE 可用”。
- `recorder_listed_not_tested`：录制器列出事件，但还没做采集；只能说“待验证”。
- `record_failed`：已经尝试但失败，不能降级描述成“未测试”；保留错误与清理结果。
- `trace_recorded`：只说明录制器生成了文件；还要检查 trace 是否能解码、地址是否对齐、是否丢包。

## 2. ETE/ETM 是什么

这一节解决“ETE 是不是自动脱壳器”的误解。

**ETM（Embedded Trace Macrocell）**是 ARM CoreSight 体系中的执行追踪源；**ETE（Embedded Trace Extension）**是较新的 ARM 追踪扩展。它们可以让 CPU 输出压缩的执行流信息，重点是分支和路径，而不是像调试器那样在每条指令后都给你一份完整寄存器快照。

一个简化的执行流可能被还原成：

```text
libfoo.so + 0x1200
  → libfoo.so + 0x1240
  → libfoo.so + 0x1308
  → libfoo.so + 0x1280
  → fault
```

它回答的是：

> “这个线程在这一小段时间里实际走了哪些路？”

它不自动回答：

> “这个私有 opcode 的语义是什么？”

也不自动产出：

```text
虚拟指令 0x37 = 加法
虚拟指令 0x42 = 条件跳转
```

### ETE 需要哪些组件

```text
CPU trace source
  → funnel（汇聚多个 source）
  → sink（ETF/ETR/TRBE 等缓冲终点）
  → perf AUX buffer
  → OpenCSD/工具解码
  → ELF 与 /proc/<pid>/maps 对地址
```

任意一段没有接通，都可能出现：

```text
simpleperf list 有 cs-etm
但 record 返回 etm devices are not available
```

这不是 root 失败，而是“录制器知道这个事件名，但没有可用 trace source”的典型形状。

**socrates 已验证例外：**设备树有 ete0–ete7，stock sink/link 与基础 CoreSight 已在，缺少 ETM4x source 驱动。归档中的匹配模块已补齐并成功采集；按 `references/ete-socrates-module.md` 核对精确基线和重载，别仅凭 funnel-ete 的名字判断。

## 3. SPE、BRBE、硬件断点和观察点

这一节解决“所有 ARM 特性都能拿来完整追踪”的误解。

### SPE：统计采样

**SPE（Statistical Profiling Extension）**更像性能分析器：它在采样点记录部分指令、访存和性能相关信息，适合找热点、缓存问题和游戏卡顿。

```text
ETE：记录程序经过了哪些路
SPE：抽样程序在哪些路上花了较多成本
```

SPE 不是完整的控制流录像，因此不应作为 OLLVM/VMP 还原的主证据。

### BRBE：有限的近期分支记录

**BRBE（Branch Record Buffer Extension）**记录有限容量的近期分支历史。它适合辅助分析崩溃前的短路径，不能当作无限长、无丢失的全程 trace。

### 硬件执行断点

CPU 在某个地址执行时触发调试异常。优点是通常不需要把目标指令改成软件断点，因此适合观察关键函数而不改变代码字节。

### 硬件观察点

CPU 在某个地址读/写时触发调试异常。它适合回答：

```text
是谁改写了校验结果？
是谁把状态变量清零？
是谁写坏了这个指针？
```

但断点和观察点都有有限槽位、对齐和大小限制。通过调试器或 `ptrace` 设置时，也可能暴露 `TracerPid`、调试状态或时序变化。

> **结论：**硬件断点是“换一种观察方式”，不是“通杀反调试”。先对未修改原始 App 做对照，再判断目标检测的到底是代码改写、调试器附加、root 环境还是工具映射。

## 4. PIE、`.so` 和三个地址空间

这一节解决 native 分析中最容易导致“反汇编看起来完全不对”的地址错误。

你会遇到三个地址：

| 地址 | 含义 | 例子 |
|---|---|---|
| 运行时地址 | 进程中 CPU 实际使用的地址 | tombstone 里的 `pc` |
| 链接时虚拟地址 | ELF 认为某段应该位于的地址 | `p_vaddr` 加函数偏移 |
| 文件偏移 | ELF 文件里的字节位置 | 用十六进制编辑器/读取器定位 |

**PIE（Position Independent Executable）**和共享库通常是 `ET_DYN`。Android 的 ASLR 会让它们每次运行映射到不同地址，所以不能把 tombstone 的 `pc` 直接拿去文件里查。

对一个 `PT_LOAD` 段，基本换算是：

```text
link_vaddr = runtime_pc - load_bias
file_offset = p_offset + (link_vaddr - p_vaddr)
```

其中 `load_bias` 不是“随便取第一行 maps 地址”：它必须和 ELF 的最低可加载段、页对齐规则一致。最稳妥的做法是同时看：

```text
/proc/<pid>/maps
ELF program headers（PT_LOAD）
```

本 skill 提供了一个只读换算器：

```bash
python skills/apk-reverse/scripts/elf_runtime.py libfoo.so \
  --runtime-address 0x7abc123456 \
  --load-bias 0x7abc000000
```

也可以反向检查文件偏移：

```bash
python skills/apk-reverse/scripts/elf_runtime.py libfoo.so \
  --file-offset 0x1234
```

### BSS 尾部的陷阱

一个 `PT_LOAD` 段可能满足：

```text
p_memsz > p_filesz
```

多出来的部分是运行时清零的 BSS，没有对应的文件字节。地址换算器会报告“在 BSS 尾部、没有文件字节”，而不是给你一个看似合理的偏移。

## 5. native 崩溃应该怎样和 trace 配合

这一节解决“有 tombstone 就等于知道原因”的误解。

建议按这个顺序：

```text
tombstone/logcat
  ↓
signal、fault addr、寄存器、backtrace
  ↓
maps 中的库与基址
  ↓
ELF PT_LOAD 地址换算
  ↓
故障指令附近反汇编
  ↓
必要时用 ETE/BRBE 看故障前路径
```

`scripts/native_crash.py` 先回答“死在哪里、什么信号、哪个库”，`elf_runtime.py`再回答“这个运行时地址对应文件哪一段”。两者不是互相替代的工具。

### 如何区分普通 bug 和故意构造的崩溃

如果 `fault addr` 是很小的常数，例如 `0x4`，并且寄存器中也保存这个数，可能是加固逻辑故意把常数当指针使用。这是一个提示，不是最终证明；还要回看故障指令和调用链。

如果是 `SIGKILL` 或干净退出，则可能根本没有 tombstone。不要因为“没有崩溃栈”就断定没有检测；检查进程退出、信号处理器和 crash reporter。

## 6. OLLVM：trace 能恢复什么，不能恢复什么

**OLLVM**是对 LLVM 编译流程做混淆的项目/变换集合。常见形态包括：

- **控制流平坦化（flattening）**：把多个真实基本块塞进一个 dispatcher（调度器）和状态变量中。
- **伪控制流（bogus control flow）**：加入实际上不会走到的垃圾分支。
- **指令替换/MBA**：用复杂的加减、异或和位运算表达原本简单的算术。

ETE、Stalker 或 QBDI 对第一类最有帮助：它们可以给出实际执行过的块和边，然后配合静态反汇编定位 dispatcher 和状态变量。

```text
trace：D → A → D → C → D → B
静态：D 写入 state，再按 state 查跳转表
结果：state 值与真实块之间建立对应关系
```

对于伪控制流，trace 中长期没有出现某条边只能成为候选，不能直接证明死代码。对于 MBA，trace 主要告诉你“走了哪条路”，不能把算术表达式自动化简；需要符号执行、输入输出差分或 SMT 求解。

现有主路线仍是：

```text
Stalker/QBDI/模拟
  → block/call 记录
  → stalker_report.py 降噪
  → 静态检查 dispatcher/state
  → 多输入验证
  → 符号执行
```

ETE 已在记录的 socrates 基线上得到经过 maps/PT_LOAD/真实 ELF 字节验证的 native 指令区间，复用入口见 `references/ete-decoding.md`；有 reset/overflow 缺口，完整块/边、调用路径及语义恢复未验证，不是必须依赖，也不是自动还原器。

## 7. VMP：trace 看到的是解释器，不是原始程序

**VMP（Virtual Machine Protection，虚拟机保护）**把原始逻辑转换成私有字节码，再由解释器执行。动态 trace 通常首先看到：

```text
取虚拟指令
  → 解码 opcode
  → 查 handler
  → 执行 handler
  → 更新虚拟 PC/栈/寄存器
  → 回到 dispatcher
```

这能帮助你找到解释器循环、handler 和热路径，但不等于恢复了原始 Java/native 逻辑。

还需要建立：

- 虚拟 PC（virtual program counter）是什么；
- 虚拟寄存器或虚拟栈在哪里；
- 每个 handler 修改了哪些状态；
- 私有 opcode 到 handler 的映射；
- 分支、异常和内存访问的语义。

Dex VMP 还要先判断方法体是否真的留在 Dex 中。若是 extraction shell，方法体只在调用时存在，ETE 追到 native interpreter 也不会凭空产生原始 Dex。现有 `vmp-differential-analysis.md` 的已知明文路线仍然只在长度和 opcode 替换前提成立时适用。

## 8. 目前的决策表

| 你要回答的问题 | 首选工具 | ETE 的位置 |
|---|---|---|
| 哪个 `.so` 真正在运行 | `lib_map.py` | 不需要 |
| tombstone 的 PC 对应文件哪里 | `elf_runtime.py` + ELF program headers | 可把 trace PC 同样换算 |
| 普通 native 崩溃原因 | `native_crash.py` + `elf_runtime.py` | 辅助故障前路径 |
| OLLVM 哪些块实际执行 | Stalker/QBDI，或成功的 ETE | 可作为低扰动 trace 后端 |
| VMP 的 interpreter 在做什么 | Frida/QBDI/模拟 + handler 分析 | 提供路径，不提供语义 |
| 谁改写了一个状态变量 | 硬件观察点/局部 hook | 不是 ETE 的任务 |
| 哪个函数耗时最多 | SPE/perf/采样 profiler | ETE 不是首选 |
| 最近发生了哪些分支 | BRBE（若设备/内核暴露） | ETE 可提供更长路径 |

## 9. 这条路线的诚实边界

- `cs_etm` 目录存在，不等于 ETE 能录制。
- `simpleperf list` 出现 `cs-etm`，不等于 ETM source 已连接。
- 生成 `perf.data`，不等于已经正确解码；还要检查丢包、模块映射和地址基准。
- trace 证明“某个输入、某个线程、某个窗口里执行过什么”，不能直接证明未出现的代码永远不可达。
- ETE 不提供寄存器/内存语义的完整快照；VMP handler 语义仍需快照、差分或模拟。
- 硬件断点/观察点不是无痕绕过；它们仍可能改变时序或暴露调试状态。
- 通用研究内核开发仍不在覆盖范围；仅发布一份已实测、精确内核的 ETE source 模块与显式重载工具，见 `references/ete-socrates-module.md`，不自动刷写或配置开机加载。

**完成标准：**把设备能力报告、采集命令、trace 文件哈希、解码器版本、ELF 文件哈希和地址映射一起保存。只写“手机支持 ETE”不构成可复现证据。
