和原版的区别，https://github.com/AloneMonkey/frida-ios-dump/，
告别卡死： 换用纯 SFTP 协议，彻底解决下载进度条经常卡在 0B 的历史 Bug。
适配新版： 完美兼容最新 Frida 17+ 的严格语法，修复大量旧版 API 导致的报错闪退。
降维打击： 弃用 ObjC 依赖，改用底层 C 函数暴力搜索内存。无视 App 的反调试与进程隔离，硬茬也能强行拔壳。
全平台兼容： 优化了老设备的注入时序防超时，且原生支持 Windows 环境完美打包。
