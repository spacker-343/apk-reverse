# 构建来源与复现检查点

这些是成功构建的输入，不是已经跨机器验证的一键构建器。

1. 在 Linux 文件系统展开 `../provenance.json` 指定的官方源码与 Clang，核对 SHA-256。
   原归档的源码提交与运行内核 build ID 不同；兼容证据来自 stock ABI 与实际运行，不是版本号伪造。
2. 官方包缺 `drivers/misc/hwid/Kconfig`，仅在构建副本删除 `drivers/misc/Kconfig`
   对不存在文件的 source 引用；保持原下载包只读。不要用占位头文件绕过 modules_prepare。
3. 使用完整同版本源码、`build.config` 与 `abi/Module.symvers`（相对本资产目录）。
   stock Image 提取 7,029 项、stock CoreSight 补充 34 项，共 7,063 项，导入交叉检查零冲突。
   不同设备/内核必须重新生成，禁止直接借本 CRC 表。
4. 宿主依赖包含 make/gcc、bison、flex、bc、libelf-dev、libssl-dev、pahole。
   以官方 LLVM 14 工具链执行 modules_prepare 与外部 Kbuild；传入
   `KERNELRELEASE=5.15.41-android13-8-00015-gde2a4c25826b-ab9439604`。
   源树的 kernel.release 规则忽略 LOCALVERSION，因此只设 LOCALVERSION 不够。
5. 将 LF 格式 `abi/Module.symvers` 放入准备好的内核输出目录；外部 `M=` 指向 `driver`。
   `driver/Makefile` 用 `__DISABLE_TRACE_MMIO__` 关闭可选 MMIO 日志，避免四个 stock 未导出符号；
   三个官方 C 文件没有修改逻辑。保留 CFI、MODVERSIONS，其他改动见 `exact-config-diff.txt`。
6. modpost/链接成功后再核对 AArch64 ET_REL、vermagic、module_layout/导入 CRC、命名空间、
   模块结构大小和 CFI 入口。`../abi/exact-module-verification.json` 是这次静态结果，不是未来结果。
   没有完整类型 vmlinux 的恢复符号 ELF 不能代替 BTF 类型基准。
7. 实际 insmod 与短时采集是最后验证；不要 `insmod -f`，不要省略 stock ABI 检查。

原资产里带会话绝对路径的过程脚本和编译 `.cmd` 没有作为可移植命令发布。
编译器匹配不证明公开源码包含厂商所有私有改动；新内核要重新验证。

## perf 核心修复（与原模块分开）

`perf-fix/README.md` 记录官方地址过滤 VMA 边界缺陷的最小 C 修复、固定源码身份、
直接原函数/修复函数对照回归，以及构建/设备验证边界。
这不修改上述三个驱动或原始 `.ko`；只有实际替换 perf 核心并复测，才可称设备修好。
