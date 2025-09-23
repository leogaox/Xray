# Xray VLESS Reality + SOCKS5（一键安装 · 极简版）

在 **Rocky Linux 9 VPS** 上一条命令部署 **Xray：VLESS+Reality(8443) + SOCKS5(1080)**。

## 系统支持
| 发行版                 | 支持度 | 说明 |
|------------------------|--------|------|
| Rocky Linux 9 (K9)     | ✅ 已验证 | 默认目标环境；脚本自动安装/启用 `docker` 与 `chronyd`，并尝试追加 MSS clamp 规则 |
| 其他 Linux 发行版      | ⚠️ 未适配 | 脚本会继续执行并提示，请自行安装 Docker 与时间同步组件 |

## 快速开始（选一种方式）

### A. Git clone
```bash
ssh root@<VPS_IP>
sudo dnf -y install git
git clone https://github.com/leogaox/Xray.git
cd Xray
sudo bash ./scripts/xray_onekey.sh install
```

### B. 下载 ZIP 上传
```bash
scp Xray.zip root@<VPS_IP>:/root/
ssh root@<VPS_IP>
unzip Xray.zip && cd Xray
sudo bash ./scripts/xray_onekey.sh install
```

### C. 仅拉取脚本
```bash
ssh root@<VPS_IP>
sudo dnf -y install curl
sudo curl -fsSL "https://raw.githubusercontent.com/leogaox/Xray/main/scripts/xray_onekey.sh" -o /root/xray_onekey.sh
sudo chmod +x /root/xray_onekey.sh
sudo /root/xray_onekey.sh install
```

### D. Raw 脚本一行安装
```bash
curl -fsSL "https://raw.githubusercontent.com/leogaox/Xray/main/scripts/xray_onekey.sh" | sudo bash -s -- install
```

## 防火墙放行
- **Rocky Linux 9（firewalld）**
  ```bash
  sudo firewall-cmd --permanent --add-port=8443/tcp
  sudo firewall-cmd --permanent --add-port=1080/tcp
  sudo firewall-cmd --reload
  ```

## 时间同步说明
- Rocky Linux 9 安装并启用 `chronyd`，脚本额外输出 `timedatectl` / `chronyc tracking` 摘要。
- 其他发行版请手动确认 NTP 已同步，确保 Reality 握手稳定。

## 常用命令
```bash
sudo bash ./scripts/xray_onekey.sh status
sudo bash ./scripts/xray_onekey.sh uninstall
sudo bash ./scripts/xray_onekey.sh purge  # 删除容器和所有配置文件
sudo docker logs --tail=80 xray-reality
ss -ltnp | egrep ':(8443|1080)\b'
```

## SOCKS5 安全策略
脚本默认启用 SOCKS5 用户名/密码认证，增强代理安全性：

### 默认安全策略
- **监听地址**：默认仅监听 `127.0.0.1:1080`（本地访问）
- **认证模式**：强制启用用户名/密码认证
- **自动生成**：未设置凭证时，脚本自动生成强随机用户名和密码

### 使用方式示例

#### 本地使用（推荐，默认配置）
```bash
sudo bash ./scripts/xray_onekey.sh install
# 安装完成后终端会显示自动生成的 SOCKS 用户名/密码
```

#### 指定自定义凭证
```bash
export SOCKS_USERNAME=alice
export SOCKS_PASSWORD='Strong-Secret-Here'
sudo bash ./scripts/xray_onekey.sh install
```

#### 对公网开放（不推荐，需自担风险）
```bash
export SOCKS_ADDR=0.0.0.0
export SOCKS_USERNAME=alice
export SOCKS_PASSWORD='Strong-Secret-Here'
sudo bash ./scripts/xray_onekey.sh install
# 并在 firewalld 中按需设置白名单或精确放行
```

### 安全警告
- **严禁** "无认证 + 公网监听" 组合
- 若确需公网使用，请务必设置强凭证并限制来源 IP
- 自动生成的凭证仅在安装时显示一次，不会写入日志文件

## 配置与数据路径
- 仓库代码可以放在任意目录，只需在执行命令前 cd 到该目录。
- 脚本默认将运行期配置与数据写入 `/srv/docker/xray`，包含 `config.json`、`reality.env` 与 Docker 卷。
- 需要指定其他路径时，可在运行命令前设置 `CONFIG_DIR=/path/to/xray`，脚本会基于该路径生成配置并维护备份。

## 可选参数
```bash
export SNI=www.cloudflare.com
export VLESS_PORT=8443
export SOCKS_PORT=1080
export SOCKS_ADDR=127.0.0.1  # SOCKS5 监听地址（默认 127.0.0.1）
export SOCKS_USERNAME=user123  # SOCKS5 用户名（未设置时自动生成）
export SOCKS_PASSWORD=pass123  # SOCKS5 密码（与用户名配对，未设置时自动生成）
export UUID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export PRIVATE_KEY="你的Reality私钥"
export PUBLIC_KEY="与你的私钥配对的Reality公钥"
export SHORT_ID="8~16位十六进制"
sudo bash ./scripts/xray_onekey.sh install
```

## 安装（Raw 脚本）
```bash
curl -fsSL "https://raw.githubusercontent.com/leogaox/Xray/main/scripts/xray_onekey.sh" | sudo bash -s -- install
```

## 下载校验（SHA256 示例）
```bash
curl -fsSL "https://raw.githubusercontent.com/leogaox/Xray/main/scripts/xray_onekey.sh" -o xray_onekey.sh
sha256sum xray_onekey.sh
# 对比发布页或自建校验值后再执行：
sudo bash xray_onekey.sh install
```

## 安全
- 不要在日志/聊天/Issue中泄露 Reality 私钥。
- 仓库已通过 .gitignore 忽略 reality.env、config.json。


## 数据清理
脚本提供两种清理方式：

### 卸载（保留配置）
```bash
sudo bash ./scripts/xray_onekey.sh uninstall
# 或使用 Makefile
make uninstall
```
删除 Docker 容器但保留所有配置文件，便于后续重新部署。

### 清除（删除所有数据）
```bash
sudo bash ./scripts/xray_onekey.sh purge
# 或使用 Makefile
make purge
```
删除 Docker 容器和所有配置文件（包括 `config.json`、`reality.env`），需要输入 `PURGE` 确认。

#### 非交互模式（自动化场景）
```bash
export XRAY_PURGE_CONFIRM=1
sudo bash ./scripts/xray_onekey.sh purge
```
设置 `XRAY_PURGE_CONFIRM=1` 可跳过交互确认，适用于自动化脚本。

## 开发与自测
- 使用 `XRAY_DRY_RUN=1` 或 `--dry-run` 可在本地渲染配置并输出执行计划，不触发 docker、systemctl、iptables 等特权操作。例如：`XRAY_DRY_RUN=1 ./scripts/xray_onekey.sh install`。
- 结合 `XRAY_MOCK_DISTRO=rocky` 覆盖包管理器路径，观察对应的依赖安装提示与防火墙指引。
- 运行 `./scripts/xray_onekey.sh selftest` 会在单次执行内模拟 Rocky 9 的首次安装与重复安装流程，验证备份动作与渲染内容是否符合预期。
- DRY-RUN 输出会对 Reality 私钥做脱敏处理，仅展示 UUID / 公钥 / Short ID 等非敏感字段。

## 排错
- 如遇 `^M` 或 `bash\r` 报错，多半是 CRLF 行尾导致，可先执行 `sed -i 's/\r$//' scripts/xray_onekey.sh` 或使用 `dos2unix` 转换后再运行。
