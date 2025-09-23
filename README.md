# Xray VLESS Reality + SOCKS5（一键安装 · 极简版）

在 **Rocky Linux 9 VPS** 上一条命令部署 **Xray：VLESS+Reality(8443) + SOCKS5(1080)**，并为 Ubuntu 22.04 / Debian 12 提供轻量适配。

## 系统支持
| 发行版                 | 支持度 | 说明 |
|------------------------|--------|------|
| Rocky Linux 9 (K9)     | ✅ 已验证 | 默认目标环境；脚本自动安装/启用 `docker` 与 `chronyd`，并尝试追加 MSS clamp 规则 |
| Ubuntu 22.04 LTS       | ✅ 已验证 | 通过 `apt-get` 安装 Docker，时间同步依赖 `systemd-timesyncd`（脚本仅启用，不额外安装 chrony）|
| Debian 12              | ✅ 已验证 | 同样使用 `apt-get` 安装 Docker；默认无防火墙，请按需配置 `iptables` 或云安全组 |
| 其他主流 Linux 发行版  | ⚠️ 部分支持 | 脚本会继续执行并提示，请自行安装 Docker 与时间同步组件 |

## 差异说明
- **包管理器**：Rocky/CentOS 使用 `dnf`，Ubuntu/Debian 使用 `apt-get`；其余发行版需预装 Docker。
- **时间同步**：Rocky 会启用 `chronyd`；Ubuntu/Debian 依赖系统自带的 `systemd-timesyncd`，如已安装 `chrony` 会自动复用。
- **防火墙**：Rocky 常用 `firewalld`，Ubuntu 常见 `ufw`，Debian 默认无防火墙（需自行配置 `iptables` 或安全组）。

## 快速开始（选一种方式）

### A. Git clone
```bash
ssh root@<VPS_IP>
sudo dnf -y install git
git clone https://github.com/leogaox/Xray.git
cd Xray
sudo ./scripts/xray_onekey.sh install
```

### B. 下载 ZIP 上传
```bash
scp Xray.zip root@<VPS_IP>:/root/
ssh root@<VPS_IP>
unzip Xray.zip && cd Xray
sudo ./scripts/xray_onekey.sh install
```

### C. 仅拉取脚本
```bash
ssh root@<VPS_IP>
sudo dnf -y install curl
sudo curl -fsSL "https://raw.githubusercontent.com/leogaox/Xray/main/scripts/xray_onekey.sh" -o /root/xray_onekey.sh
sudo chmod +x /root/xray_onekey.sh
sudo /root/xray_onekey.sh install
```

## 防火墙放行（按发行版）
- **Rocky / CentOS（firewalld）**
  ```bash
  sudo firewall-cmd --permanent --add-port=8443/tcp
  sudo firewall-cmd --permanent --add-port=1080/tcp
  sudo firewall-cmd --reload
  ```
- **Ubuntu（ufw）**
  ```bash
  sudo ufw allow 8443/tcp
  sudo ufw allow 1080/tcp
  sudo ufw reload
  ```
- **Debian 12 / 其他**：默认可能未开启防火墙，请确认云安全组或 `iptables` 已开放 TCP 8443/1080。

## 时间同步说明
- Rocky 安装并启用 `chronyd`，脚本额外输出 `timedatectl` / `chronyc tracking` 摘要。
- Ubuntu/Debian 默认启用 `systemd-timesyncd` 即可；若已安装 `chrony` 将尝试启动。
- 其他发行版请手动确认 NTP 已同步，确保 Reality 握手稳定。

## 常用命令
```bash
sudo ./scripts/xray_onekey.sh status
sudo ./scripts/xray_onekey.sh uninstall
sudo docker logs --tail=80 xray-reality
ss -ltnp | egrep ':(8443|1080)\b'
```

## 可选参数
```bash
export SNI=www.cloudflare.com
export VLESS_PORT=8443
export SOCKS_PORT=1080
export UUID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export PRIVATE_KEY="你的Reality私钥"
export PUBLIC_KEY="与你的私钥配对的Reality公钥"
export SHORT_ID="8~16位十六进制"
sudo ./scripts/xray_onekey.sh install
```

## 一行安装命令（Raw 脚本）
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


## 开发与自测
- 使用 `XRAY_DRY_RUN=1` 或 `--dry-run` 可在本地渲染配置并输出执行计划，不触发 docker、systemctl、iptables 等特权操作。例如：`XRAY_DRY_RUN=1 ./scripts/xray_onekey.sh install`。
- 结合 `XRAY_MOCK_DISTRO=rocky|ubuntu|debian` 覆盖不同包管理器路径，观察对应的依赖安装提示与防火墙指引。
- 运行 `./scripts/xray_onekey.sh selftest` 会在单次执行内模拟 Rocky 9、Ubuntu 22.04、Debian 12 的首次安装与重复安装流程，验证备份动作与渲染内容是否符合预期。
- DRY-RUN 输出会对 Reality 私钥做脱敏处理，仅展示 UUID / 公钥 / Short ID 等非敏感字段。
