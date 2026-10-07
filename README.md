# empty-city-ctf · 空城计

一个 Windows x86 逆向 CTF 题目，包含正式源码、构建工具、早期实验和完整题解。

> 我写程序是为了出题，题都出出去了，我还写程序做什么。

选手附件中的 `source.c` 只有一个返回 0 的 `main`。真正的逻辑由 PE TLS 回调启动，通过 VEH 修改异常上下文进入 `.data` 中的机器码，读取当前工作目录里的 `flag` 文件，再使用 XTEA 校验输入。

**本仓库包含真实源码、Flag 和题解，有剧透。** 想先挑战题目，请从 [Releases](https://github.com/mio-qwq/empty-city-ctf/releases) 下载 `empty_city_players.zip`。

## 题目概览

| 项目 | 内容 |
| --- | --- |
| 题目名称 | 空城计 |
| 类别 | Reverse |
| 平台 | Windows x86 / PE32 |
| 选手附件 | `empty_city.exe`、`source.c` |
| 输入方式 | 当前工作目录中的小写 `flag` 文件 |
| 校验算法 | XTEA，32 个 cycle，小端 32 位字，独立 8 字节分组，PKCS#7 填充 |

执行流程：

```text
TLS 回调 → 注册 VEH → 触发整数除零
                         ↓
                 VEH 修改 CONTEXT.Eip
                         ↓
                  .data 中的主体
                         ↓
              字符串还原 → 读取 flag → XTEA 校验
                                         ↓
                                   正确时显示弹窗
```

## 项目结构

```text
empty-city-ctf/
├── src/           正式题目的 C 入口和 NASM 汇编
├── config/        题目文案、Flag 和密钥配置
├── scripts/       构建、工具链查找、选手附件打包
├── tools/         常量生成、PE 检查、运行验收
├── solutions/     Python 和 Node.js 求解器
├── examples/      早期 x86 / x64 demo、TLS / VEH 探针
├── docs/          完整 WP 和分析截图
├── dist/          选手附件源码及生成的发布文件
└── LICENSE        使用许可
```

真实构建入口是 `src/empty_city.c`，机器码逻辑在 `src/blob.asm`。`dist/source.c` 是题目设定中的趣味附件。

本地构建还会生成 `build/`；原始备份和历史分析资料保存在本机的 `local/`。两者以及 EXE、ZIP、IDA 数据库均已被 Git 忽略。

## 构建与验收

需要 Windows、Node.js、NASM，以及安装了 C++ 桌面工具和 Windows SDK 的 Visual Studio / Build Tools。Python 3.10+ 用于 Python 求解器。Node.js 脚本只使用标准库，无须安装 npm 依赖。

在项目根目录打开 PowerShell：

```powershell
.\scripts\build.ps1
node .\tools\check-pe.mjs
.\tools\verify.ps1
.\scripts\package-release.ps1
```

脚本从 `PATH` 查找 NASM，通过 `VSINSTALLDIR` 或 `vswhere` 查找 Visual Studio；也可以显式指定工具路径：

```powershell
.\scripts\build.ps1 -Nasm 'D:\Tools\nasm\nasm.exe' -VsRoot 'D:\Tools\VisualStudio'
```

构建生成 `dist/empty_city.exe`，打包生成 `dist/empty_city_players.zip` 和 `dist/SHA256SUMS.txt`。ZIP 只包含 EXE 和附件源码。

`check-pe.mjs` 检查 PE 布局、TLS、节属性、导入和题目明文残留。`verify.ps1` 执行 19 项运行验收，覆盖输入缺失、长度与编码错误、7 个分组分别改错、工作目录语义和正确答案弹窗；它会自动关闭自身测试进程的弹窗。报告在 `build/reports/`。

## 运行与解题

程序读取进程**当前工作目录**中的 `flag`，输入必须是 49 字节 ASCII，无 BOM、无末尾换行。缺失文件、打开失败、长度不符或校验失败时，程序静默退出；正确输入会显示成功弹窗。

构建时会生成正确输入 `build/author/flag`。从项目根目录验证：

```powershell
Push-Location .\build\author
try { ..\..\dist\empty_city.exe } finally { Pop-Location }
```

两个求解器都从 EXE 中提取密钥与密文，不读取答案配置：

```powershell
python .\solutions\solve_empty_city.py
node .\solutions\solve.mjs
```

完整分析过程、19 张截图和代码附录见 [空城计 WP](docs/writeup.md)。

## 早期实验

各示例可从项目根目录单独构建，也支持 `-VsRoot`：

| 示例 | 构建入口 | 输出目录 |
| --- | --- | --- |
| x64 TLS / VEH demo | `examples/demo-x64/build.ps1` | `build/examples/demo-x64/` |
| x64 全局数值 blob | `examples/blob-x64/build.ps1` | `build/examples/blob-x64/` |
| x86 全局数值 blob | `examples/blob-x86/build.ps1` | `build/examples/blob-x86/` |
| x86 TLS 探针 | `examples/probes/build_tls.ps1` | `build/examples/tls-probe-x86/` |
| x86 VEH 探针 | `examples/probes/build_veh.ps1` | `build/examples/veh-probe-x86/` |

TLS / VEH 探针分别返回预期退出码 7 / 25。旧 `blob-x64` 实验在当前主机以 `0xC0000409` 退出，整理前的二进制也存在该问题；正式题目不依赖这一实验。

## 环境说明

正式题目使用 `/NXCOMPAT:NO`，`.data` 没有执行权限标记，也不调用 `VirtualProtect`。能否运行依赖目标 Windows 的 DEP 策略；脚本不会修改系统 DEP 设置。IDA 的自动分析结果可能因版本和设置不同而变化。

2026-10-07 本机验收：正式题目重新构建成功，PE 检查、19 项运行检查和两份求解器全部通过；只导出 Git 待提交文件到新目录后，也能够完成构建与求解。

## 许可证

采用 [Limited Source Code License / 有限源代码许可证](LICENSE)。使用条件、额外授权方式及联系方式以许可证全文为准。
