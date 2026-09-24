# NightWatch

> 我挺喜欢那种“看起来没问题，但就是哪里不对劲”的日志。

这是我自己折腾的一个本地安全事件关联与行为检测引擎，主要用来研究登录行为、网络连接、周期外联、DNS 异常这些东西。

我不太想一上来就堆一整套 SIEM，也不想为了“看起来高级”先做一堆仪表盘。

先把数据喂进去，把时间窗口、行为关系、证据链和误报想明白，再谈界面。

```text
登录失败 ─────┐
端口高扇出 ────┼─> 事件关联 -> 告警 -> 实体风险 -> JSON / Markdown
周期外联 ──────┤
高熵 DNS ──────┘
```

## 现在能抓什么

| 规则 | 检测思路 | 核心信号 |
|---|---|---|
| `AUTH-SEQ-001` | 连续登录失败后短时间成功 | sequence correlation |
| `NET-SCAN-001` | 单源对单目标端口高扇出 | sliding window |
| `NET-BEACON-001` | 低抖动周期性外联 | interval CV |
| `DNS-TUNNEL-001` | 长、高熵 DNS Label | entropy heuristic |

每条告警都会保留时间窗口和触发证据。

我不太喜欢那种最后只告诉我一句：

```text
suspicious = true
```

但不告诉我为什么可疑的检测器。

所以 NightWatch 里每个规则尽量都能回答三个问题：

- 哪个实体触发了；
- 在什么时间窗口里触发；
- 到底是哪组数据让它触发。

## 快速跑一下

```bash
git clone https://github.com/LLR6/Cybersecurity-Detection-Engineering-Android-Automation-Learning-by-Building.git
cd Cybersecurity-Detection-Engineering-Android-Automation-Learning-by-Building

python -m venv .venv
pip install -e ".[dev]"

pytest -q

nightwatch samples/demo.jsonl --format md --out report.md
```

示例 Beacon 告警：

```json
{
  "rule_id": "NET-BEACON-001",
  "score": 82,
  "entity": "10.10.7.12->203.0.113.42:443",
  "evidence": {
    "interval_mean": 30.0,
    "interval_cv": 0.0,
    "samples": 7
  }
}
```

这个例子里，连接平均每 30 秒出现一次，而且时间抖动几乎为 0。

单独看一条连接没什么，但把时间序列拉出来以后，味道就不太一样了。

## 我比较在意的东西

### 时间关系比单行匹配更重要

很多真正有意思的行为，不会出现在某一行日志里。

比如：

```text
失败
失败
失败
失败
失败
成功
```

单看最后那个“成功”完全正常。

但如果前面刚连续失败了很多次，这个成功就值得重新看一眼。

所以 NightWatch 现在很多逻辑都是围绕：

```text
事件 + 时间窗口 + 前后关系
```

来做。

### 告警必须带证据

我希望以后看到一条告警，不需要重新打开源码，也能大概判断：

```text
为什么响？
响得有没有道理？
下一步该查什么？
```

所以每条 Alert 都会带 `evidence`。

### 能不用依赖就先不用

核心检测目前基本只吃 Python 标准库。

不是因为依赖越少越“高级”，而是我希望：

```text
git clone
pip install
直接跑
```

别为了一个简单检测器先起半天环境。

### 误报不是 bug，是检测设计的一部分

高熵 DNS 不等于 DNS Tunnel。

周期连接也不等于 C2。

端口高扇出也不一定就是扫描。

这些东西都只是 Signal。

检测器的任务是把值得继续看的东西捞出来，不是替分析人员直接下结论。

## Beacon 检测

目前的 Beacon 规则会计算连续连接之间的时间间隔：

```text
30s
30s
29s
31s
30s
30s
```

然后计算均值和变异系数：

```text
CV = 标准差 / 平均值
```

如果间隔足够稳定，而且样本数量达到阈值，就会形成告警。

目前只是比较基础的版本，后面我准备继续加：

- jitter 容忍；
- 分桶统计；
- 长时间基线；
- 同主机多目的关联；
- 工作时间 / 非工作时间差异。

## DNS 检测

现在会看：

```text
Label 长度
字符分布
Shannon Entropy
完整域名长度
```

例如这种：

```text
aZ8fK2mQ9xP7cV4nR6tY1uI3oL5sD0hJ.telemetry.example
```

不会因为“长得奇怪”就直接判恶意，而是把它作为中等风险信号。

后面想继续加：

- 子域唯一率；
- NXDOMAIN 比例；
- 请求频率；
- 单客户端域名基线；
- TXT 查询行为；
- 域名长度分布异常。

## 风险融合

我不太喜欢把几个分数直接粗暴相加。

所以目前同一个实体上的多条告警会做一个简单风险融合：

```text
risk = 1 - product(1 - score_i)
```

这样做的好处是：

弱信号叠加以后会变得更值得关注，但又不会随便两条告警就直接冲到几百分。

例如：

```text
Beacon + DNS 异常 + 认证异常
```

比单独出现其中一个更值得看。

## 项目结构

```text
src/nightwatch/
├── models.py
├── detectors.py
├── engine.py
├── report.py
└── cli.py

tests/
samples/
docs/
.github/workflows/
```

`detectors.py` 只负责检测逻辑。

`engine.py` 做调度和风险聚合。

`models.py` 统一事件和告警结构。

`report.py` 负责输出。

我现在尽量不把东西全塞进一个文件里，不然后面一旦加规则，很快就会变成一坨。

## 自动测试

仓库里有 pytest 测试，覆盖目前几类核心检测：

```text
认证失败 -> 成功
端口扫描
周期 Beacon
高熵 DNS
风险聚合
```

GitHub Actions 每次提交都会自动：

```text
安装
↓
跑测试
↓
执行 demo
↓
生成 Markdown 检测报告
↓
上传 artifact
```

比“我本地能跑”靠谱一点。

## 下一步想继续挖的坑

- Zeek 日志适配
- Suricata eve.json 适配
- PCAP -> Flow 特征提取
- 类 Sigma 的 Sequence Rule
- ATT&CK Technique 映射
- 主机行为画像
- Beacon Baseline
- Precision / Recall 测试集
- 多阶段攻击链关联
- 图关系展示
- SARIF 输出
- CI 安全门禁

我更想把这个项目慢慢做成：

```text
能解释
能复现
能测试
能扩展
```

而不是“功能很多，但自己过一个月都看不懂”。

---

项目仅用于防御安全研究、实验环境、安全分析和合法授权场景。
