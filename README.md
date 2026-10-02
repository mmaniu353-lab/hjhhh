# VPN Gate 住宅出口订阅

本项目把 VPN Gate 的 SSTP 中继接入自有 Cloudflare Worker，定期筛选后发布到 GitHub Pages。住宅分类来自出口 ASN 和运营商信息，是估算，不能保证检测网站会给出相同标签。

客户端订阅：[mihomo.yaml](https://mmaniu353-lab.github.io/hjhhh/mihomo.yaml)。节点集合：[proxies.yaml](https://mmaniu353-lab.github.io/hjhhh/proxies.yaml)。

原 Worker 的 `/sub?token=自己的订阅令牌` 地址也支持修复后的完整配置：FlClash/Mihomo/Clash 的请求直接返回上述 YAML，浏览器下载时添加 `&target=clash`。沿用原来的令牌鉴权；令牌不会发送给 GitHub，也不要提交到仓库。修复配置不可用时返回 503，客户端保留现有配置，不回退到旧的 DNS 模板。订阅响应的更新提示为 1 小时，配置内的节点集合仍每 15 分钟更新。

## 检测与自动切换

GitHub Actions 在每小时的 7、22、37、52 分钟计划运行，GitHub 可能延迟任务。每个节点必须连续两次通过自有检查器，返回有效且一致的公共出口 IP，再通过实际 VLESS → Worker → SSTP 链路访问 Google 和 Cloudflare 的 HTTPS 204 页面。HTTPS 证书验证保持开启，HTTP 状态不符、TLS EOF、超时均剔除。这个检测使用 HTTPS HEAD；Cloudflare trace 仅用于另外的 GET 出口验证，不能用作 HEAD 200 检测。

候选节点并发取自官方 HTTPS CSV、GitHub 镜像和本项目上次发布的 `data.json`，按 `host:port` 去重。官方接口成功时仍合并镜像独有的节点；上次结果仅在生成时间不超过 24 小时且字段有效时用于发现地址，最多补充 512 个候选，每个都重新经过两次出口检查和完整 HTTPS 链路验证。设置 `MAX_CHECK_NODES` 限制检测数量时优先日本候选。源地址标注的国家与实测出口不同，以检查器确认的出口国家码分组。

自动订阅每 15 分钟更新节点集合，每 2 分钟做 HTTPS 健康检查。“日本住宅自动”使用 `url-test`，从本机完整链路的健康节点中选择更快的日本住宅出口，延迟差在 100 毫秒内时减少来回切换；其他国家组每 3 分钟检查并故障切换。选择“住宅出口 → 日本住宅自动”等国家组后，避免跨国家轮换影响登录会话。测速和故障切换仍然会改变出口 IP。自动组没有健康节点时使用 REJECT；全部住宅节点未通过发布检测时，任务失败并保留上次已部署版本。

发布节点按实测 `https_latency_ms` 排序，缺失或无效测量排在最后；记录的已验证入口仍在当前入口清单中时，排序后继续使用该入口。检查器的 `latency_ms` 包含出口信息查询时间，不作为完整链路速度的排序依据。本机自动测速结果也可能与 GitHub Actions 不同，以客户端的实际链路为准。

健康检查通过完整代理链路请求 `https://1.1.1.1/`，验证 TLS 证书及 HTTP 301，不跟随跳转。使用 IP 地址省去测速域名的额外 SSTP DNS 建连；此 URL 不用于 DNS 解析器配置。发布前仍必须通过 Google 和 Cloudflare 两个域名的 HTTPS 204 检查，以验证域名解析和实际网站访问。第一条入口失败时再验证第二条入口，发布保留成功的入口。检查器通过 SSTP 访问自有 `/ip.json`，避免第三方 IP 查询接口限流；住宅属性依照 ASN 和中继类型估算，Cloudflare 未提供的隐私/托管标记保持未知。

节点名称绑定 `host:port` 的摘要，排序变化不会把同一个名称映射到另一个出口。传统 `chains.txt`、`hosts.txt`、`sub.txt` 仍会生成；需要自动更新和故障切换时使用完整 Mihomo YAML。

长对话建议选择默认的“日本住宅稳定”：按完整 HTTPS 延迟排序后的候选故障切换，避免仅因另一节点快一点而切换。“日本住宅自动”仍可用于测速选优；故障切换和节点列表更新仍可能改变出口 IP。发布检查另外要求连续两次独立 HTTPS 建连，剔除只偶尔握手成功的线路。

自有检查器的 `EXIT_METADATA_KEY` 必须配置为 Cloudflare Secret；带随机 nonce 的出口响应使用 HMAC-SHA256 认证，并检查签名及 60 秒有效期。密钥只保存在 Worker 环境中。未配置密钥时检查失败，不信任中继返回的未认证地区和运营商信息。

SSTP 内层 TCP 保留最多 65,535 字节未确认数据，尊重接收窗口，校验并处理累计/部分 ACK，丢包后按 1/2/4/8 秒间隔补发。没有确认进展时约 23 秒结束连接，零窗口阻塞最多 30 秒；关闭和中止会清理重传与等待任务。隧道每 20 秒主动发送 SSTP Echo，健康空闲链路不再因固定 60 秒读超时被误关，无响应的中继仍按时退出。这是现有简化 TCP 的有限修复，未实现完整拥塞控制、SACK 或 FIN 重传；免费志愿节点离线仍需要重新检测及故障切换。

## Windows / FlClash

需要支持当前 Mihomo 配置的客户端，本项目以 Mihomo v1.19.32 验证。导入完整 YAML，使用配置自身的 DNS，关闭“追加系统 DNS”，启用 TUN。FlClash 会用应用设置覆盖配置中的 TUN 开关，仅在 YAML 中写 `enable: true` 并不足以开启应用的 TUN。

网站 DNS 通过所选住宅出口访问 Google TCP DNS，失败后不会回退到直连 DNS。DNS 随 VLESS/TLS 和 SSTP 加密到住宅出口，从出口到 Google 使用 TCP53；减少额外 DoH 握手造成的首次查询超时。Worker 收到 SSTP 目标域名或 UDP53 查询时，也通过同一个 SSTP 节点解析。

CI 入口采用实测通过的 `172.64.155.1` 和 `172.64.144.1`，并保留自有 Worker 域名的 TLS SNI 与 Host。此次本机两条入口的 Cloudflare colo 为 SIN，自有域名的 TLS 与 trace 请求分别约 328/406 毫秒；同一组 13 个日本候选的完整链路验证中，新入口通过 8 个、旧入口通过 7 个，冷连接延迟中位数由约 5.41 秒降至 4.18 秒。Cloudflare Anycast 路由可能变化，此数据不代表长期速度保证。`EDT_ENTRY_IPS` 可覆盖；不设置时使用自有 Worker 域名解析出的 IPv4。

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
node cloudflare/tests/subscription.cjs
node --test cloudflare/tests/checker.cjs
MIHOMO_BINARY=/absolute/path/to/mihomo python vpngate.py
```

CI 下载官方固定版本 Mihomo 并验证归档 SHA256；不设置 `MIHOMO_BINARY` 的本地运行会明确跳过真实 HTTPS 验证。`VPNGATE_API`、`VPNGATE_MIRROR`、`EDT_DOMAIN`、`EDT_UUID`、`CHECK_WORKER`、`SITE_URL` 可通过环境变量覆盖；历史候选只读取 `SITE_URL/data.json`。
