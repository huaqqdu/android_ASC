# asc-mcp — droidasc 的 MCP 封装

把 [droidasc](https://github.com/MG1937/ASC)（ASC：毫秒级的 Android/APK 反编译器）包成
MCP server，供 DSH（或任何 MCP 客户端）以工具形式调用。每个工具就是对 `droidasc` CLI 的一次
子进程调用，返回文本。

本目录随 [huaqqdu/android_ASC](https://github.com/huaqqdu/android_ASC)（ASC 的 fork）一起分发：
**克隆这一个仓库就同时拿到反编译器与 MCP server**，不必另外维护第二份代码。

## 快速开始

```bash
# 1. 拿代码（反编译器 + MCP server）
git clone https://github.com/huaqqdu/android_ASC && cd android_ASC

# 2. 装 CLI（editable：以后 git pull 即生效）
uv venv --python 3.10 /opt/droidasc/venv
uv pip install --python /opt/droidasc/venv/bin/python --editable .
ln -sf /opt/droidasc/venv/bin/droidasc /usr/local/bin/droidasc

# 3. 装 MCP server 的运行环境（只有标准库 + mcp SDK 一个依赖）
uv venv --python 3.10 /opt/asc-mcp/venv
uv pip install --python /opt/asc-mcp/venv/bin/python mcp
```

不需要 `uv` 也行：把上面两条 `uv venv` 换成 `python3.10 -m venv <路径>`，
`uv pip install` 换成 `<路径>/bin/pip install`。

## 组成

| 路径 | 作用 |
| --- | --- |
| `asc-mcp/server.py` | MCP server（stdio），8 个工具；纯 stdlib + `mcp` SDK，不 import droidasc |
| `asc-mcp/test/smoke.py` | 用官方 MCP 客户端起进程、列工具、真调一次（可带 APK 路径） |
| `/opt/droidasc/venv` | CLI 运行环境（editable 指向本仓库） |
| `/opt/asc-mcp/venv` | server 运行环境（Python 3.10 + `mcp`） |

server 不 import droidasc，只调 `droidasc` 可执行文件，因此反编译器升级（`git pull`）与
server 改代码互不影响。

## 工具

| 工具 | 做什么 | 关键参数 |
| --- | --- | --- |
| `apk_info` | 包名 / 版本 / min-target-compileSdk / dex 数 / ABI / 权限数（不解压反编译，最快） | `apk` |
| `apk_manifest` | AndroidManifest.xml → XML | `apk`, `output_path` |
| `apk_list_classes` | 列 Dalvik 类描述符，按前缀过滤，按行分页 | `apk`, `prefix`, `offset`, `limit` |
| `apk_decompile_class` | 单类 → Java 源码 | `apk`, `class_name`, `threads`, `output_path`, `max_chars` |
| `apk_disassemble_class` | 单类（或单个方法）→ smali | `apk`, `class_name`, `method`, `debug_info` |
| `apk_find_refs` | 跨全部 dex 找引用 | `apk`, `query`, `kind`, `class_name`, `fuzzy_class`, `offset`, `limit` |
| `apk_strings` | 搜字符串池：硬编码 URL、API key、提示语 | `apk`, `pattern`, `regex`, `ignore_case`, `min_len`, `sources`, `offset`, `limit` |
| `apk_smali_grep` | 跨类 grep smali 指令：反射、加解密、日志/网络特征 | `apk`, `pattern`, `class_prefix`, `class_names`, `max_classes`, `jobs`, `regex`, `offset`, `limit` |

`kind` 取值：`string` / `type` / `method` / `field` / `extends` / `impl`。
`extends`、`impl` 用来枚举继承某类、实现某接口的所有类。

### `apk_strings` 的三个来源

| `sources` | 读什么 | 适合找 |
| --- | --- | --- |
| `dex` | 所有 `classes*.dex` 的 string_ids 池（自己解析 DEX header，不经 CLI） | 代码里的常量：域名、API 路径、密钥、AES 模式串 |
| `arsc` | `resources.arsc` 顶层字符串池（UTF-8/UTF-16 池都支持） | XML 里写的文案、地址、配置 |
| `raw` | 解压 `assets/`、`res/raw/`、json/js/txt 等文本文件后抓可打印串 | 壳的配置、H5 资源、混淆器的字典 |

默认 `dex,arsc`。QQ 实测：2,597,671 条 dex 串 + 63,243 条 arsc 串，一次扫完约 6 秒。
`pattern` 为空 = 不过滤（只要 `min_len` 以上），结果按出现顺序去重后分页。

### `apk_smali_grep` 为什么要设上限

它没有索引可用：对**每个候选类**跑一次 `droidasc disassemble` 再逐行匹配。所以：

- 用 `class_prefix` 收窄（如 `Lcom/tencent/mobileqq/utils/`），或直接用 `class_names` 点名；
- `max_classes` 默认 200、上限 1000，`jobs` 默认 8 并发；QQ 实测 60 个类 / 8 并发约 5 秒；
- 超出上限会在头部提示"还有 N 个类没扫"，缩小前缀继续扫。

例：`pattern='Ljava/lang/reflect/Method;->invoke'` 找反射入口；
`pattern='Ljavax/crypto/Cipher;->doFinal'` 找加解密落点。

### 输出怎么读

- 大结果默认截断到 60k 字符，末尾会说明总长。
- `apk_list_classes` / `apk_find_refs` / `apk_strings` / `apk_smali_grep` 都是**按行分页**的，
  回 "还有 N 行，offset=X 继续"。
- 任何带 `output_path` 的工具会把全文写进文件，只回前 40 行预览——大文件（几 MB 的 Java）走这条。

失败不会只回 "Error executing tool"：路径不存在、CLI 退出码非 0、超时都会把原因放进正文，
以 `ERROR:` 开头。

## 注册到 DSH

写进 profile 的 patch 层（**热加载**，不重启 `dsh web` 就生效）：

`~/.dsh/profiles/web/cordis.patch.yml`

```yaml
- insert:
    - id: asc-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: asc
        transport: stdio
        command: /opt/asc-mcp/venv/bin/python
        args:
          - /path/to/android_ASC/asc-mcp/server.py
        toolCallTimeoutMs: 300000
        startupTimeoutMs: 60000
        failOnStartupError: true
```

把 `args` 里的路径换成你克隆下来的仓库位置。工具名 = `mcp__asc__<tool>`，
例如 `mcp__asc__apk_decompile_class`。
（`~/.dsh/cordis.patch.yml` 是全局层，只在启动时读；要热改就用 profile 层。）

## 验证

```bash
/opt/asc-mcp/venv/bin/python asc-mcp/test/smoke.py /path/to/some.apk
```

八项全过 = 握手、工具清单、错误路径、apk_info、分页、apk_strings、apk_smali_grep 都正常。
不带 APK 参数时就只跑前两项（握手 + 工具清单 + 错误路径）。

## 运维

- **升级**：`cd android_ASC && git pull` —— CLI 是 editable 安装，拉下来即生效；
  `asc-mcp/server.py` 也一起更新。
- **改 server.py 后让运行中的客户端加载新代码**：MCP 客户端持有长连接，
  改 profile patch 会触发热加载；只改了 `server.py` 的话，结束 MCP 子进程
  （`pgrep -f asc-mcp/server.py` 后 `kill`）让客户端重连即可，不必重启 `dsh web`。
- **换 venv / 换 Python**：同步改 patch 里的 `command`。
- **日志**：server 的错误走 stderr，客户端会带上 "Error executing tool" 或连接诊断。

## 已知限制

- 只覆盖 DEX 层：`getclass`/`findrefs`/`listclass`/`getmanifest`/`disassemble` 这五个能力
  （`apk_strings` 的字符串池与 `apk_smali_grep` 的逐类反汇编也都在 DEX 层）；
  **native `.so` 不在范围**（用 IDA/REA 那边）。
- 每次调用都重新打开 APK、按需解析，没有跨调用缓存：冷调用 0.3–0.6s（392MB 的 QQ APK 实测），
  同一 APK 上连续做几十次分析会比 JADX 那种"先全量索引"的模型慢一截，但省内存、无需预处理。
- `apk_list_classes` 对超大包可能几十万行（QQ 42.8 万行），务必用 `prefix` 收窄。
- `--threads` 只对 `getclass`/`listclass`/`findrefs` 有意义，默认由 CLI 决定。
