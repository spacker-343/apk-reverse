# 原 ETE 运行记录（精选脱敏副本）

来源：工作区 `ete-assets/socrates-5.15.41-2026-10-13` 的 README、EXACT-ETM-RUNTIME-REPORT、
runtime-result.json、simpleperf-record.stderr、内核初始化日志。不是这次发布重新做的 insmod。
设备序列号、boot UUID、主机绝对路径、无关系统日志与 trace 不发布。

- `insmod ... boot_enable=0 pm_save_enable=1` 返回 0；模块 Live。
- CPU0–CPU7 全部输出 `ete v1.0 initialized`，八个平台 source 绑定。
- root、modules_disabled=0，SELinux Enforcing，加载前后 boot ID 相同。
- 未写持久分区，未配置自动加载。
- stock 导出/CRC/CFI/结构检查见 `../abi/exact-module-verification.json`。

原 simpleperf 输出：

```text
simpleperf I cmd_record.cpp:729] Recorded for 1.1141 seconds. Start post processing.
simpleperf I cmd_record.cpp:799] Aux data traced: 2166016
```

原命令（设备 root shell）：

```sh
simpleperf record -e cs-etm:u --aux-buffer-size 1048576 \
  --no-dump-symbols --no-dump-kernel-symbols \
  -o /data/local/tmp/ete-exact-smoke.data -- /system/bin/ls /system/bin
```

record 返回 0，文件 2,433,042 字节，SHA-256
`a0dd42cb482a7351073845a01d6f05d23e569e795888e7b6f48bb6ecbc7ac67f`。
`simpleperf dump` 返回 0，显示 cs-etm:u event_attr、auxtrace_info、AUXTRACE。
结束后八个 source enable_source=0，模块仍 Live；相关日志未发现 CFI/Unknown symbol/CRC/Oops/panic。
设备端测试数据已删除。

`observed` 只到硬件 AUX 采集和文件结构。**未完成 packet/element 与指令路径闭环解码**；
真实 APK/OLLVM/VMP、地址过滤、内核态、睡眠唤醒与长时稳定性均未验证。
旧构建失败的唯一根因不明，成功不能倒推出只因 Clang 或 SELinux。
