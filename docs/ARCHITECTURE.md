# NightWatch 架构笔记

目前整个数据链路很简单：

```text
JSONL
  ↓
事件标准化
  ↓
多个 Detector 并行检测
  ↓
Alert 集合
  ↓
实体风险融合
  ↓
Markdown / JSON 报告
```

我暂时没有急着做复杂规则语言。

原因也很简单：检测规则写出来不难，真正麻烦的是把事件语义、时间窗口、证据和误报边界想清楚。

## Event

所有输入先统一成 Event。

现在主要字段有：

```text
ts
kind
src
dst
user
port
query
status
action
```

原始事件仍然保留在 `raw` 里，避免标准化以后把信息丢掉。

## Detector

每个 Detector 都是独立函数：

```text
events -> alerts
```

规则之间尽量不共享状态。

这样做主要是为了两个东西：

- 单元测试好写；
- 某条规则炸了，不容易把其他规则一起拖死。

目前比较典型的几类规则：

```text
sequence(auth.fail x N -> auth.success) within 120s

fanout(net.dst_port) >= N within 60s

periodicity(net.flow) cv <= threshold

feature(dns.label_entropy) >= threshold
```

以后如果规则多起来，再考虑抽 DSL。

现在直接上 DSL，我感觉有点为了抽象而抽象。

## 风险融合

同一个 Entity 可能同时触发多个规则。

目前风险不是直接求和，而是：

```text
risk = 1 - product(1 - score_i)
```

比如同一台主机既有：

```text
周期外联
DNS 异常
认证行为异常
```

那它应该比只触发一条弱规则更值得优先调查。

## 目前故意没做的东西

### 数据库

现在输入量还没大到需要数据库。

先把 Detector 做扎实。

### Web Dashboard

Dashboard 很好看，但现在不是核心问题。

等数据模型和告警模型稳定以后再做，不然只是把不稳定的数据漂亮地画出来。

### ML

目前也不急着上机器学习。

很多行为检测用统计特征、时间窗口和基线就能先做出比较能解释的结果。

以后真加模型，我也希望模型是在规则检测基础上补能力，而不是把所有东西扔进黑盒。

## 后续方向

我比较想继续做三层：

```text
L1  单事件特征
L2  时间窗口行为
L3  多实体攻击链
```

最终希望能做到：

```text
单条日志
  ↓
局部行为
  ↓
主机画像
  ↓
多阶段活动
```

这比单纯做一堆正则规则有意思得多。
