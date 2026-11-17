---
doc-id: PWNHUST-DEV-001
title: pwn.hust.college 部署偏差补遗（DV-1 / DV-2）
version: 1.0
verified: 2026-11-17
verified-against: https://pwn.cse.hust.edu.cn（CTFd + dojo，道馆 software-security）
applies-to: pwnhustcollege 技能（SKILL.md）Phase 1 与 Phase 3
self-link: references/deployment-deviations.md
self-anchors: "#dv-1", "#dv-2", "#sec-integrate", "#sec-verify", "#sec-provenance"
supersedes: []
---

# pwn.hust.college 部署偏差补遗

## 0. 这份文档是什么（自引用）

本文档是 `pwnhustcollege` 技能的**补遗参考**，不是一份独立的教程。它记录的
两条偏差，会让"照 SKILL.md 一步步做"的 agent 在 Phase 1（连上目标）和
Phase 3（生成并运行 exploit）之前就卡死。

**本文档引用自身的方式：**

| 自引用要素 | 值 | 用途 |
|---|---|---|
| 文件路径 | `references/deployment-deviations.md` | 从 `SKILL.md` 链接过来时的相对路径 |
| 稳定编号 | `DV-1`、`DV-2` | 跨文档引用；编号一旦发布不再变更 |
| 锚点 | `#dv-1`、`#dv-2`、`#sec-integrate`、`#sec-verify`、`#sec-provenance` | 精确引用到小节 |
| 引用式写法 | `见 deployment-deviations.md#dv-2` | 推荐在 SKILL.md 与故障报告里使用的写法 |
| 证伪方式 | 见 [§4](#sec-verify) | 若上游已修复，按 §4 判定并把本文档标记为过期 |
| 证据台账 | 见 [§5](#sec-provenance) | 每条断言都能回溯到原始输出 |

**接入位置**：把本文件放到技能仓库的 `references/deployment-deviations.md`，
并在 `SKILL.md` 末尾追加 [§3](#sec-integrate) 给出的片段。§3 里那段文字
本身就是在描述"如何引用本文档"，因此本文档在被接入后依然是自洽的——
删除本文档会导致 `SKILL.md` 中 `DV-1` / `DV-2` 两个引用悬空，这一点是
刻意设计的：悬空引用即是"补遗缺失"的告警信号。

**适用前提**：agent 运行在 **Windows + DSH 文件沙箱（workspace-write）**，
目标平台是 **`pwn.cse.hust.edu.cn`**（不是 `pwn.hust.college`，见 §2.0 脚注）。
超出这个前提时，本文档的结论需重新验证。

---

<a id="dv-1"></a>

## DV-1 — `/challenge/solve` 不是契约，可执行文件名必须现场枚举

### 1.1 症状

照 SKILL.md 的写法直接执行：

```bash
/challenge/solve
```

等价的现象是 `No such file or directory`、`cat: /challenge/solve: 没有那个文件或目录`，
或 agent 在生成 exploit 时把 `/challenge/solve` 硬编码进 `process("/challenge/solve")`
导致 pwntools 抛 `FileNotFoundError`。

### 1.2 错误假设链

1. pwn.college 上游文档大量出现 `/challenge/solve`；
2. → 被当成平台契约写进技能；
3. → agent 跳过 `ls`，直接拼路径；
4. → 在本部署上必然失败，且失败信息看起来像"容器没起来"，容易误判为容器问题。

### 1.3 实际行为

本部署的挑战文件由 dojo 的 `insert_challenge()` 放入 `/challenge`，文件名**来自
挑战自身的构建产物**，不是固定名。实测 `simple-demo:level-1-0`：

```console
$ ls -la /challenge/
total 16
drwsr-xr-x 1 root root 4096 Nov 17 03:09 .
drwxr-xr-x 1 root root 4096 Nov 17 03:10 ..
-rwsr-xr-x 1 root root   55 May 15  2024 DESCRIPTION.md
-rwsr-xr-x 1 root root 282 May 15  2024 simple-demo-level1.0
```

注意三点：

- **没有 `solve`**；
- 文件名是 `<module>-level<x>.<y>` 形态；
- `chmod -R 4755` 作用于整个目录，所以连 `DESCRIPTION.md` 都是 `-rwsr-xr-x`。
  不要拿"SUID 位"当作定位挑战程序的判据——它对本目录里所有文件都成立。

命名规律也不可靠。同一 dojo 里存在文件名与模块名**不一致**的关卡：

| 模块目录 | 实际可执行文件 |
|---|---|
| `simple-demo/level-1-0` | `simple-demo-level1.0` |
| `buffer-overflow/level-1-0` | `buffer-overflow-level1.0` |
| `pwntools-tutorials/level-1-0` | `pwntools-tutorials-level1.0` |
| `setuid-backdoor/level-1-0` | `setuid-backdoor-level1.0` |
| `return-oriented-programming/level-1-0` | `return-oriented-programming-level1.0` |
| **`other-vulnerabilities/level-1-0`** | **`format-string-level1.0`** ← 不一致 |

最后一行是关键证据：**不能由模块名推导文件名**。

### 1.4 正确做法

把"定位挑战程序"变成一个显式动作，永不拼路径。推荐的最小实现：

```python
rc, out, _ = run(c, "ls -la /challenge/")
# 取 /challenge 下的普通文件，排除 DESCRIPTION.md，按 SUID 或可执行优先
```

`recon.sh` 应当先做：

```bash
ls -la /challenge/
file /challenge/* 2>/dev/null | grep -v DESCRIPTION
```

在 pwntools 里则改为运行时发现，而不是常量：

```python
import glob, os
cands = [p for p in glob.glob("/challenge/*")
         if os.path.isfile(p) and not p.endswith("DESCRIPTION.md")]
target = cands[0]          # 单文件关卡；多文件时按可执行位筛选
context.binary = ELF(target)
```

### 1.5 判据

当且仅当以下命令**都不为空**时，才算定位成功：

```bash
ls /challenge/ | grep -v '^DESCRIPTION.md$'
```

---

<a id="dv-2"></a>

## DV-2 — Windows 沙箱下无法把私钥交给 OpenSSH，改用 paramiko

这一条覆盖"从零到一条可用 SSH 通道"的全过程：**生成密钥 → 注册到平台 →
在本机建立连接**。三个环节在 Windows + DSH 沙箱下各有一个坑，且失败信息互相
掩盖，逐个说明。

### 2.0 前提：用对域名

`pwn.hust.college` 在本机被代理（Clash 类 TUN）解析为 fake-ip `198.18.148.160`，
TLS 握手返回**证书域名不匹配**。真实入口是：

```
https://pwn.cse.hust.edu.cn
```

SSH 也连 `pwn.cse.hust.edu.cn:22`。看到 `Hostname mismatch, certificate is not
valid for 'pwn.hust.college'` 时，不要怀疑 token 或网络，换域名即可。

### 2.1 症状 A — `ssh-keygen` 产不出公钥

```console
$ ssh-keygen -t ed25519 -f key -N "" 
Unable to save public key to key.pub: Bad file descriptor
```

结果：私钥 `key` 写成了（411 字节），公钥 `key.pub` 是 **0 字节**，而且之后
连删除/覆写都失败：

```console
>>> open(d/"key.pub", "w")
PermissionError: [Errno 13] Permission denied: '...\\key.pub'
```

根因：沙箱给新建文件打了 **Low 完整性标签**，`icacls` 显示

```
Mandatory Label\Low Mandatory Level:(I)(NW)
```

### 2.2 症状 B — `icacls` 修不了权限

Windows OpenSSH 强制校验私钥 ACL，于是：

```console
Bad permissions. Try removing permissions for user: UNKNOWN\UNKNOWN (S-1-4-517573781-758814669) on file .../id_pwn.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions for 'id_pwn' are too open.
Load key "id_pwn": bad permissions
hacker@pwn.cse.hust.edu.cn: Permission denied (publickey).
```

直觉做法是收紧 ACL，但沙箱把 `WRITE_DAC` 也挡掉了：

```console
$ icacls id_pwn /inheritance:r
id_pwn: Access is denied.
$ icacls id_pwn /grant:r "%USERNAME%:F"
id_pwn: Access is denied.
```

文件 ACL 里那条异常 SID `S-1-4-517573781-758814669` 是沙箱注入的，不受
用户控制。**结论：在 workspace-write 模式下，不要试图通过改 ACL 让 OpenSSH
接受私钥——这条路是死的。**

### 2.3 症状 C — 顺带：原生进程输出捕获被禁

同一模式下还有一条会伪装成"ssh 坏了"的现象：

```console
$ ssh -V 2>&1
程序'ssh.exe'运行失败： Access to the path '\\.\pipe\LOCAL\dotnet_...' is denied.
```

以及 `curl`：

```console
$ curl ... 
curl: (35) schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS
```

两条都不是 ssh/curl 的问题，而是：沙箱禁命名管道（任何 `.NET` 管道式捕获），
以及 schannel 拿不到凭证存储。**这直接否定了"用 subprocess 包一层 ssh"的思路。**

### 2.4 正确做法 — 全 Python，进程内加载私钥

绕开三件事：不调用 `ssh.exe`（绕开 ACL 与管道）、不用 `ssh-keygen`（绕开
完整性标签）、不用 schannel（用 Python 的 OpenSSL）。

**第一步，用 `cryptography` 生成密钥对**：

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

key = ed25519.Ed25519PrivateKey.generate()
open("id_pwn", "wb").write(key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,          # 必须是 OpenSSH 格式
    encryption_algorithm=serialization.NoEncryption()))

pub = key.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH).decode()
pub = " ".join(pub.split()[:2])                          # 去掉尾部注释
open("id_pwn.pub", "w", newline="\n").write(pub + "\n")
```

**第二步，注册公钥**（字段名是 `ssh_key`，不是 `key`）：

```python
POST /pwncollege_api/v1/ssh_key   {"ssh_key": "<ssh-ed25519 AAAA... 裸密钥>"}
```

**第三步，用 paramiko 连接**：

```python
import paramiko

pkey = paramiko.Ed25519Key.from_private_key_file("id_pwn")   # 进程内解析，不查 ACL
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("pwn.cse.hust.edu.cn", 22, username="hacker", pkey=pkey,
          timeout=30, allow_agent=False, look_for_keys=False)

_, out, _ = c.exec_command("hostname; ls -la /challenge/")
print(out.read().decode())
```

服务端对 `hacker` 强制 `command="enter.py user_<id>"`，所以你发过去的任何命令
都会经 `enter.py` 转成 `docker exec user_<id> /opt/pwn.college/ssh-entrypoint -c "<cmd>"`，
无需自己处理容器。

### 2.5 密钥槽位：`POST` 的报错是歧义的，用 `DELETE` 探测

这是本部署最耗时的一个坑。上传公钥时：

```console
POST   /pwncollege_api/v1/ssh_key  {"ssh_key": "<K>"}
  → 400 {"success": false, "error": "SSH Key already in use"}
```

这句话**并不表示 `<K>` 重复**。源码（`dojo_plugin/api/v1/ssh_key.py`）里它是
`IntegrityError` 的统一文案：

```python
try:
    key = SSHKeys(user_id=user.id, value=key_value)
    db.session.add(key); db.session.commit()
except IntegrityError:
    return {"success": False, "error": "SSH Key already in use"}, 400
```

而线上库对同一 `user_id` 事实上只容一条记录。于是**任何**新密钥都会得到这句
提示，与密钥本身无关。分辨方法只有一个：

```console
DELETE /pwncollege_api/v1/ssh_key  {"ssh_key": "<K>"}
  → 200 {"success": true}                     ⇒ <K> 确实在库里
  → 400 {"error": "SSH Key does not exist"}   ⇒ <K> 不在库里，槽位被别的密钥占着
```

推论与处置：

- `DELETE` 显示 `<K>` 存在 → 是你的，可以直接用；
- `DELETE` 显示不存在、但 `POST` 仍报 `already in use` → **槽位被一把你无法
  控制的旧密钥占着**（平台搭建或前次会话遗留）。此时不能靠"再传一次"解决，
  必须在 Web UI（Settings → SSH Key）里由账号持有人删除该旧密钥，然后重新
  `POST`。这一步 agent 自己做不了，应当直接向用户请求。
- 曾出现**注册成功并可用之后再次失效**、且 `DELETE` 报 `does not exist` 的情况
  ——说明密钥在会话期间被外部改动过。遇到这种情况，先按上面的 `DELETE`
  探测确认真实状态，不要盲目重试 `POST`（重试只会拿到同一句歧义报错）。

### 2.6 不要做的事

| 不要 | 原因 |
|---|---|
| 用 `icacls` / `chmod` 修私钥权限 | 沙箱拒绝 `WRITE_DAC`，`Access is denied` |
| 用 `subprocess` 调 `ssh.exe` | 命名管道被禁，`\\.\pipe\... denied` |
| 用 `ssh.exe` 直接读私钥 | ACL 校验必失败，与密钥内容无关 |
| 用 `ssh-keygen` 生成密钥 | 公钥写不出（0 字节），文件随后不可写 |
| 把 `curl` 当 HTTP 客户端 | schannel `SEC_E_NO_CREDENTIALS`，改用 Python `urllib` |
| `POST` 失败就反复重试 | 报错歧义，重试不会改变状态 |

---

<a id="sec-integrate"></a>

## 3. 如何接入技能（self-integrate）

在 `SKILL.md` 末尾追加：

```markdown
## 部署偏差（必读）

本部署与上游 pwn.college 存在两处偏差，会让下面的流程在开始阶段就失败：

- **DV-1**：`/challenge/solve` 不是契约，挑战二进制必须现场枚举
- **DV-2**：Windows 沙箱下私钥不能交给 OpenSSH，改用 paramiko

细节、证据与判据见 `references/deployment-deviations.md#dv-1` 与
`references/deployment-deviations.md#dv-2`（文档编号 `PWNHUST-DEV-001`）。
```

同时把 SKILL.md 中所有 `/challenge/solve` 的硬编码改为"先 `ls /challenge/`"，
把 `ssh -i <key>` 的执行方式改为 paramiko 等价实现。

---

<a id="sec-verify"></a>

## 4. 自我证伪（何时本文档过期）

逐节跑下面的检查。**任何一项都不再复现时，对应小节应标记为过期**，
而不是被默默删除——过期记录本身对后来者有价值。

**DV-1**

```bash
ls -la /challenge/                       # 是否出现了一个叫 solve 的文件？
test -e /challenge/solve && echo "DV-1 可能已修复"
```

**DV-2**

```bash
ssh.exe -V 2>&1                                  # 是否还报 named pipe denied？
icacls <key> /inheritance:r                      # 是否还 Access is denied？
ssh.exe -i <key> hacker@pwn.cse.hust.edu.cn id   # 是否还报 UNPROTECTED PRIVATE KEY FILE？
```

三项中任一项行为改变，DV-2 需重新验证并升 `version`。

---

<a id="sec-provenance"></a>

## 5. 证据台账

| 项 | 值 |
|---|---|
| 采集时间 | 2026-11-17（Asia/Shanghai） |
| 目标 | `https://pwn.cse.hust.edu.cn`，道馆 `software-security` |
| 账号 | CTFd user id = 1 |
| 现场关卡 | `simple-demo:level-1-0`（容器 hostname `simple-demo~level-1-0`） |
| 验证身份 | `uid=1000(hacker) gid=1000(hacker)` |
| DV-1 直接证据 | `ls -la /challenge/` 输出见 §1.3；仓库 `hust-open-atom-club/software-security-dojo-x64`@main 文件树见 §1.3 表格 |
| DV-2 直接证据 | `ssh-keygen` 报 `Bad file descriptor`；`icacls` 报 `Access is denied`；`ssh.exe` 报 `UNPROTECTED PRIVATE KEY FILE`；paramiko 连接成功 |
| 端到端结果 | 以 paramiko 执行 `/challenge/simple-demo-level1.0` 取到 flag，`POST /api/v1/challenges/attempt` 返回 `{"status": "correct"}` |
| 平台源码 | `github.com/hust-open-atom-club/pwn.hust.college` 分支 `hustsec_dev` |

---

## 6. 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 1.0 | 2026-11-17 | 首版。DV-1 / DV-2 建立，附 §2.5 密钥槽位探测法 |
