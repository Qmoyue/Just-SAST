# Just — 架构设计

## 1. 目标

轻量字节码 SAST：对 JAR/WAR 挖掘 Java 反序列化 gadget 利用链。单 JAR 交付，零外部服务。

## 2. 总体架构

```
JAR/WAR → ASM 前端（fat jar/WAR 嵌套 + JDK 懒加载）
  → CPG（CHA 调用图 + 可见性剪枝，构建后冻结）
  → 黑板三阶段调度（12 个知识源）
      ANALYSIS:     反向污点 ∥ 前向污点 ∥ OIS 回调 ∥ 框架桥接
      COMPOSITION:  对象图扩散 → 片段合成 → 语义链组装
      CALIBRATION:  校验 → 剪枝 → SafeConfig → 模式识别 → 动态验证
  → 置信度 → 六格式输出
```

## 3. 知识源（12 个）

| KS | 包 | 阶段 (priority) | 职责 |
|---|---|---|---|
| BackwardTaint | backward | ANALYSIS (100) | 从 sink 反向回溯可控性（per-sink 并行，段级记忆化） |
| ForwardTaint | engine | ANALYSIS (200) | 前向污点不动点（粗扫+精扫单引擎两轮，精扫 parallelStream） |
| OisCallback | ois | ANALYSIS (300) | resolveClass/resolveProxyClass 回调建模 |
| FrameworkBridge | framework | ANALYSIS (400) | 规则驱动框架桥接（12 marshaller） |
| ObjectGraph | objectgraph | COMPOSITION (100) | 对象图入口扩散（字段类型回调重根） |
| Fragment | fragment | COMPOSITION (150) | chain-fragment 规则合成已知链 |
| ChainComposer | compose | COMPOSITION (200) | INVOKE/TRIGGER/TEMPLATE/DESER 语义桥接 |
| ChainValidator | calibrate | CALIBRATION (100) | PASM + 类型流 + 序列化可行性 + 约束图矛盾 |
| ChainPruner | calibrate | CALIBRATION (200) | 触发上下文 + 深链结构门 + 机制去重（软预算） |
| SafeConfig | calibrate | CALIBRATION (300) | 安全配置抑制（偏移序校验） |
| GadgetPattern | calibrate | CALIBRATION (400) | 已知模式标注（集合包含判定） |
| Verify | calibrate | CALIBRATION (500) | 反射构造可行性 + 子进程链级动态验证 |

调度：ANALYSIS 并行派发（自足契约 + join 屏障），COMPOSITION/CALIBRATION 按 priority 串行。

## 4. 核心分析

### 4.1 调用图

- CHA 传递子类型闭包分发
- 可见性剪枝（private/static/跨包 package-private 不可覆写）
- DISPATCH_CAP=200 超限时闭包做全子类型展开
- LAMBDA 边用 resolveMethod 后的声明类

### 4.2 反向污点

- 从 sink 反向回溯，直到 magic entry
- 可控语义：OIS 读 / 入口 this / proxy args / 字段 / 数组 / passthrough
- **反射跳边**：常量类 `getMethod/getDeclaredMethod` 的 invoke 位点视为目标类 public 方法的伪调用者
- **JavaBean 反射跳**：`getReadMethod/getWriteMethod` 模式 → getter 前缀方法目标（万能类型走 wildcard）
- **入口距离调度**：sink 与调用者按入口 BFS 距离升序——预算优先花在高可达成区
- **段级记忆化**：`方法X→入口Y` 结论跨 sink 复用（JDD IOCD 精神）
- per-sink 有序 work-stealing（16 worker 自适应）

### 4.3 前向污点

- 粗扫（类级事实）→ 精扫（接口/代理/反射精化）单引擎两轮共享
- MODEL 规则消费：`this←argN` 容器投毒 / `return←src` 透传
- origin-guided 分发精度：NEW→精确类、FieldRead→声明类型

### 4.4 入口闭包

- 从 magic entry + OIS 宿主 BFS
- DISPATCH_CAP 超限展开（抽象类子类型全枚举）
- 反射跳展开 + JavaBean wildcard 直接种子
- 距离表供调度使用

### 4.5 校准

- Validator 五层：PASM 可行性 / 类型流（非 final 无共同子类即拒） / 序列化可行性 / equals 卫式降级 / 约束图矛盾
- catch 可达性守卫：CCE 类型安全 cast / 受检反射必成功 / 确定性运行时异常无可抛源
- 深链结构门：动态分派跳 >14 且字段流 <17% 剪
- Pruner 软预算：前 8 家族保留，高证据溢出链 DEGRADED
- 四级判定：FEASIBLE / DEGRADED(reason) / NOT_FEASIBLE

### 4.6 动态验证（子进程链级）

自动执行（无 CLI 开关），流程：

1. **候选选择**（`ParallelVerifier.selectChains`）：按证据分值降序取候选，同一入口类最多 2 条——预算优先覆盖入口多样性
2. **链级探针**（`ChainVerifyProbe`）：解析链的 FIELD_FLOW 跳（`owner.field=targetClass`），自底向上反射实例化并按字段链接成完整对象图，再触发入口方法
3. **sink 特异性判定**：检查子进程堆栈是否包含 sink 类——SINK_TRIGGERED（真到达 sink）> EXECUTED（链执行完成）> PARTIAL_PATH（中途异常，链保留不拒）
4. 预算有界（20 条、4 路并行）；CONFIRMED 链在 findings.csv 置顶并携带 `verify:confirmed` 注释

## 5. 规则系统

5 种类型（sink / magic-entry / source / model / chain-fragment），全在 YAML。

- sink：owner/name/descriptor 匹配 + 层次命中
- magic-entry：方法匹配 + implements + `access: private` 过滤
- source：框架入口 + `safe-config` 声明块（偏移序抑制）
- model：声明式污点透传（actions）
- chain-fragment：声明式已知链（entryClass/hops/sinkOwner，后缀匹配支持 repackaged）

## 6. 前端

- fat jar（BOOT-INF）+ WAR（WEB-INF）嵌套 jar 递归（深度 4）
- 装载顺序 target → deps → JDK
- label 引用缺失即失败（不静默假边）
- `--jdk-home`：Java 8 读 rt.jar，Java 9+ URLClassLoader 挂载目标 jrt-fs.jar

## 7. 输出

CSV 四表 + SARIF + JSON/HTML/Markdown（共 9 文件）。CSV 流式写出（大语料 10 万+ 变体链不整表驻留内存）。

## 8. 基准

Gleipner evaluator（`benchmark/Gleipner/run-gleipner.sh` + `GleipnerOut.java` 转换器，本地不入库）：

**当前**：链覆盖 TP **106/122**、FP 块 **22/47**（官方 evaluator 块计数为 147/22——Just 报告比基准粒度更细的路径变体，块计数偏高；上表 Just 行采用与其他工具可比的链覆盖率口径）

| 工具 | TP | FP |
|---|---|---|
| Crystallizer | 105 | 76 |
| **Just** | **106** | **22** |
| Serianalyzer | 81 | 28 |
| SerHybrid | 80 | 40 |
| GadgetInspector | 78 | 23 |
| Tabby | 67 | 17 |

差异化优势：multipath 10/10（GadgetHunter 1/10）、depth 18/20（GadgetHunter 14/20）、polymorphism 20/20。
