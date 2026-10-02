# VPN Gate 住宅出口订阅

本项目把 VPN Gate 的 SSTP 中继接入自有 Cloudflare Worker，定期筛选后发布到 GitHub Pages。住宅分类来自出口 ASN 和运营商信息，是估算，不能保证检测网站会给出相同标签。

客户端订阅：[mihomo.yaml](https://mmaniu353-lab.github.io/hjhhh/mihomo.yaml)。节点集合：[proxies.yaml](https://mmaniu353-lab.github.io/hjhhh/proxies.yaml)。

## 检测与自动切换

GitHub Actions 在每小时的 7、22、37、52 分钟计划运行，GitHub 可能延迟任务。每个节点必须连续两次通过自有检查器，返回有效且一致的公共出口 IP，再通过实际 VLESS → Worker → SSTP 链路访问 Google 和 Cloudflare 的 HTTPS 204 页面。HTTPS 证书验证保持开启，HTTP 状态不符、TLS EOF、超时均剔除。这个检测使用 HTTPS HEAD；Cloudflare trace 仅用于另外的 GET 出口验证，不能用作 HEAD 200 检测。

自动订阅每 15 分钟更新节点集合，每 3 分钟做 HTTPS 健康检查，在同国家组内故障切换。选择“住宅出口 → 日本住宅自动”等国家组后，避免跨国家轮换影响登录会话。切换节点仍然会改变出口 IP。全部住宅节点失败时，任务失败并保留上次已部署版本。

节点名称绑定 `host:port` 的摘要，排序变化不会把同一个名称映射到另一个出口。传统 `chains.txt`、`hosts.txt`、`sub.txt` 仍会生成；需要自动更新和故障切换时使用完整 Mihomo YAML。

## Windows / FlClash

需要支持当前 Mihomo 配置的客户端，本项目以 Mihomo v1.19.32 验证。导入完整 YAML，使用配置自身的 DNS，关闭“追加系统 DNS”，启用 TUN。FlClash 会用应用设置覆盖配置中的 TUN 开关，仅在 YAML 中写 `enable: true` 并不足以开启应用的 TUN。

网站 DNS 通过所选住宅出口访问 Google TCP DNS，失败后不会回退到直连 DNS。DNS 随 VLESS/TLS 和 SSTP 加密到住宅出口，从出口到 Google 使用 TCP53；减少额外 DoH 握手造成的首次查询超时。Worker 收到 SSTP 目标域名或 UDP53 查询时，也通过同一个 SSTP 节点解析。

入口采用实测通过的两条 Cloudflare IPv4，并保留自有 Worker 域名的 TLS SNI 与 Host。此次本机测试中，两条入口的 Cloudflare colo 为 LAX，原自有域名地址的 colo 为 AMS，优化后的隧道内 TCP DNS 用时约 2.3–3.5 秒。Cloudflare Anycast 路由可能变化，此数据不代表长期速度保证。`EDT_ENTRY_IPS` 可覆盖；不设置时使用自有 Worker 域名解析出的 IPv4。

直连的加密 bootstrap DNS 用于节点入口或订阅下载域名，不承担网站 DNS。阿里 DNS 使用证书名称 `dns.alidns.com` 校验，未关闭证书验证。订阅下载走 DIRECT，因此本机需要能访问 GitHub Pages。

## Worker 修复

`cloudflare/worker.mjs` 基于原部署的 cmliu/edgetunnel `af4f9837e1843e34159018713bc8749ccec3004d`，修复 SSTP DNS 旁路、PPP/SSTP Echo 响应、SYN 重试、接收重复及乱序数据、ACK/FIN/RST 处理和关闭行为。保留线上 Worker 的 UUID、ADMIN、KV、兼容日期等现有设置，只替换代码。不要把账号令牌或 KV 设置提交到仓库。

该 Worker 的 SSTP 实现仍是简化 TCP，不具备完整操作系统 TCP 的发送重传与拥塞控制；免费 VPN Gate 中继也可能随时离线。它可以减少已定位的故障，但不能承诺商业线路的可用性。长连接应针对实际使用的网站继续验证。

DNS 检测中显示多个 Google DNS IP，或 DNS 与住宅宽带属于不同 ASN，本身不能证明本地 DNS 泄漏。应核对是否出现本地运营商、并检查查询是否经过所选住宅出口。

## 本地验证

```sh
pip install -r requirements.txt
python -m unittest discover -s tests -v
node cloudflare/tests/dns.cjs cloudflare/worker.mjs
node cloudflare/tests/run.mjs
MIHOMO_BINARY=/absolute/path/to/mihomo python vpngate.py
```

CI 下载官方固定版本 Mihomo 并验证归档 SHA256；不设置 `MIHOMO_BINARY` 的本地运行会明确跳过真实 HTTPS 验证。`EDT_DOMAIN`、`EDT_UUID`、`CHECK_WORKER`、`SITE_URL` 可通过环境变量覆盖。
