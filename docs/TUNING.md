# NightWatch Tuning Notes

NightWatch 把检测结果看成 **需要继续调查的信号**，而不是自动定性的结论。调参的目标不是“告警越少越好”，而是在可解释的前提下控制噪声。

## 1. Case gap

`--case-gap` 控制两个共享实体告警在时间上最多相隔多少分钟仍可进入同一个 Case。

- 太小：同一活动容易被切成多个 Case。
- 太大：共享基础设施或 NAT 环境可能把无关活动错误聚合。
- 默认 30 分钟只是工程起点，不代表适合所有环境。

建议用真实已标注事件回放，观察 Case fragmentation 与 accidental merging。

## 2. Suppression

`--suppressions` 接收 JSON 文件。每条规则包含：

- `rule_id`：支持 glob，例如 `NET-BEACON-*`
- `entity`：支持 glob，例如 `10.10.20.*->203.0.113.10:443`
- `reason`：必须写清楚为什么这是已知正常行为

抑制不是删除证据。配合 `--suppressed-out`，NightWatch 会输出被排除告警的规则、实体、分数、匹配模式和原因。

这使得“为什么今天没有看到这条告警”仍可审计。

## 3. Suppression hygiene

推荐：

1. 尽量写窄匹配，不要轻易使用 `*` 覆盖整个规则。
2. reason 写业务原因，而不是“误报”两个字。
3. 定期复核长期 suppression。
4. 变更 suppression 时保留 Git 记录。
5. 对新环境先观察，再抑制。

## 4. Evidence first

每个 detector 至少应回答：

- 哪个实体触发；
- 何时开始、何时结束；
- 哪个统计量或事件序列触发；
- 哪条规则触发；
- 如果有 ATT&CK 映射，映射基于什么证据。

新规则如果只能输出 `suspicious=true`，不应直接加入核心 detector 集合。

## 5. Evaluation backlog

后续希望补齐：

- 带标签事件集；
- 每条规则的 Precision / Recall；
- suppression 前后告警量变化；
- Case 合并/拆分误差；
- 规则阈值敏感性；
- Zeek / Suricata 字段缺失情况下的退化行为。

NightWatch 的目标不是追求一个漂亮的单一准确率，而是把 **信号、证据、聚合、抑制、人工判断** 之间的关系做得透明。
