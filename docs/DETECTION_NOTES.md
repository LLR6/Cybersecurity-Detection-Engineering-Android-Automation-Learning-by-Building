# 检测笔记

这个文件主要记规则为什么这么写，而不是再抄一遍代码。

## 关联比单点更有意思

端口扫描本身不稀奇，几次登录失败也不稀奇。但如果同一个来源先做服务探测，几分钟后连续认证失败，最后又认证成功，这个序列就比任何一个单点都更值得看。

CHAIN-001 当前看的就是：服务探测 -> 连续认证失败 -> 认证成功。

它不是在证明入侵，只是把调查优先级抬高。

## 为什么 Beacon 暂时不硬贴 ATT&CK

只看到 src -> dst:443 每 30 秒出现一次，还不足以判断它到底用了什么应用层协议，更不足以直接给出具体 C2 Technique。

所以 NET-BEACON-001 目前不强行绑定 ATT&CK。我宁愿少一个标签，也不想让标签比证据跑得更快。

## ATT&CK 映射

| Rule | ATT&CK |
|---|---|
| AUTH-SEQ-001 | T1110 Brute Force |
| NET-SCAN-001 | T1046 Network Service Discovery |
| DNS-TUNNEL-001 | T1071.004 DNS |
| CHAIN-001 | T1046 + T1110 |

这些映射只是分析上下文，不是恶意判决。

## Adapter

Suricata EVE 和 Zeek 日志都会先转成统一 Event。Detector 不关心数据原来是谁产的。

Suricata / Zeek -> Event -> Detector -> Alert

这样后面接 Sysmon、Windows Event Log、Linux auditd、Falco 时，只需要继续写 Adapter，不用把检测逻辑一起改烂。

## 后面更想解决的问题

- Host / User / IP 实体归一化
- 长时间行为基线
- 跨数据源关联
- 更完整的证据链
- 误报评估和 Precision / Recall

规则数量看起来很爽，但如果不知道为什么响、误报多少，数量本身没多大意义。