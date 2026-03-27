frida-ios-dump (Pro / Refactored)
基于 AloneMonkey 原版 frida-ios-dump 的深度重构版。(https://github.com/AloneMonkey/frida-ios-dump/)

原版脚本是业内非常经典的 iOS 砸壳工具，但随着 Frida 迭代到 17.x（全面引入严格的 QuickJS 引擎）以及现代 iOS 越狱环境的演进，原版脚本在实际使用中经常会遇到“进度条卡死 0B”、“JS 语法报错崩溃”、“ObjC 环境未就绪”等各种水土不服的问题。

为此，本仓库对底层通信协议、JS 注入逻辑和内存操作进行了大量现代化重构，专为现代 iOS 逆向环境打造。

🔥 核心更新与修复 (Changelog)
1. 修复 SCP 传输假死 (卡死在 0.00B)
痛点： 现代 iOS 越狱机 (iOS 14+) 的 OpenSSH 已逐渐弃用老旧的 scp 协议，导致原版 Python 脚本在拉取文件时容易无限期握手等待。

重构： 全面弃用系统 scp 命令，改为使用 Paramiko 原生 SFTP 协议。针对越狱机 SSH 性能较弱的特点，强制禁用了 SFTP 的 prefetch（预取机制），彻底解决了大体积 App 多文件并发拉取时的假死与丢包问题。

2. 完美适配 Frida 17.x 与 QuickJS 引擎
痛点： 原版大量使用了被 Frida 官方彻底废弃的老旧 API（如 Memory.readU32()），在高版本环境中会直接抛出 TypeError 导致砸壳瞬间闪退。

重构： 将所有内存读写辅助函数全面升级为 NativePointer 专属方法（如 addr.readU32()）。同时修复了原版中隐蔽的 JS 语法 Bug（例如 magic == FAT_CIGAM || FAT_MAGIC 恒成立导致的 1600 万次死循环），彻底消灭了 access violation 内存越界问题。

3. 摆脱 ObjC 运行时依赖，提升反调试对抗能力
痛点： 原版极度依赖高级 API（ObjC.classes.NSBundle）获取应用路径，遇到 Shadowrocket 等带有反调试、无 UI 守护进程，或故意污染 JS 命名空间的 App 时直接失效。

重构： 剥离 ObjC 依赖，改用底层 C 函数（open, read, lseek）进行内存操作。引入 Process.enumerateModules() 暴力遍历内存特征抓取 .app 路径，配合 ApiResolver 动态解析 C 函数，即使 App 内部污染了全局变量也能强行绑定导出函数完成脱壳。

4. 修复注入时序竞争 (解决 ObjC is not defined)
痛点： 原版在性能较弱的老设备（如 iPhone 6s）上，往往 App 业务刚跑起来 ObjC 运行时还没加载完，JS 就打进去了，导致脚本直接报错超时。

重构： 重构了 App 的生命周期控制，严格执行 Spawn 唤醒 -> 挂起 -> 完整注入 JS -> Resume 恢复运行 流程，确保 Frida 的 Hook 环境绝对早于核心业务就绪，彻底解决因注入时机引发的偶发性失败。

5. 原生跨平台兼容 (Windows 免环境打包)
痛点： 原版代码硬编码了 Linux/macOS 的专属终端命令（如 chmod 赋权、zip 打包），导致 Windows 用户在最后一步打包 .ipa 时必报错。

重构： 引入 platform 系统检测，自动跳过 Windows 不支持的赋权指令；移除对外部 zip 命令的依赖，采用 Python 内置的 shutil.make_archive 进行纯净的跨平台打包。现在 Mac / Linux / Windows 三端通杀，开箱即用。
