# Just — 架构设计

## 1. 目标

轻量字节码 SAST：对 JAR/WAR 挖掘 Java 反序列化 gadget 利用链。单 JAR 交付，零外部服务。

## 2. 总体架构

```
JAR/WAR → ASM 前端（fat jar/WAR 嵌套 + JDK 懒加载）
  → 轻量代码图（CHA 调用图 + 字段写入索引，构建后冻结；CFG/def-use 由分析引擎按需惰性计算）
  → 黑板三阶段调度（12 个知识源）
      ANALYSIS:     反向污点 ∥ 前向污点 ∥ OIS 回调 ∥ 框架桥接
      COMPOSITION:  对象图扩散 → 片段合成 → 语义链组装
      CALIBRATION:  校验 → 剪枝 → SafeConfig → 模式识别 → 动态验证
  → 置信度 → 六格式输出
```

物化的图结构为「METHOD/CALL 节点 + 调用/分发/LAMBDA 边」的轻量调用图与字段写入侧索引；
方法内 CFG 由 `Cfg` 纯函数现算，值来源由 `ForwardOrigins` 惰性抽象解释，均不落图。

## 3. 知识源（12 个）

| KS | 包 | 阶段 (priority) | 职责 |
|---|---|---|---|
| BackwardTaint | backward | ANALYSIS (100) | 从 sink 反向回溯可控性（per-sink 并行，段级记忆化） |
| ForwardTaint | engine | ANALYSIS (200) | 前向污点不动点（粗扫+精扫单引擎两轮，拓扑序处理） |
| OisCallback | ois | ANALYSIS (300) | resolveClass/resolveProxyClass 回调建模 |
| FrameworkBridge | framework | ANALYSIS (400) | 规则驱动框架桥接（12+ marshaller） |
| ObjectGraph | objectgraph | COMPOSITION (100) | 对象图入口扩散（字段类型回调重根） |
| Fragment | fragment | COMPOSITION (150) | chain-fragment 规则合成已知链 |
| ChainComposer | compose | COMPOSITION (200) | INVOKE/TRIGGER/TEMPLATE/DESER 语义桥接 + 源宿主容器触发桥 |
| ChainValidator | calibrate | CALIBRATION (100) | PASM + 类型流 + 序列化可行性 + 约束图矛盾 |
| ChainPruner | calibrate | CALIBRATION (200) | 触发上下文 + 深链结构门 + 机制去重（软预算） |
| SafeConfig | calibrate | CALIBRATION (300) | 安全配置抑制（偏移序校验） |
| GadgetPattern | calibrate | CALIBRATION (400) | 已知模式标注（集合包含判定） |
| Verify | calibrate | CALIBRATION (500) | 反射构造可行性 + 子进程链级动态验证 |

调度：ANALYSIS 并行派发（自足契约 + join 屏障），COMPOSITION/CALIBRATION 按 priority 串行。
事件机制：CHAIN_FOUND 跨阶段延迟投递（当前阶段无订阅者则回填队列，后续阶段可消费）。

## 4. 核心分析

### 4.1 调用图

- CHA 传递子类型闭包分发（`ClassHierarchy.transitiveSubtypes` 记忆化，调用图与引擎侧展开同源）
- 可见性剪枝（private/static/跨包 package-private 不可覆写）
- DISPATCH_CAP=200 超限时闭包做全子类型展开
- LAMBDA 边用 resolveMethod 后的声明类
- JSR/RET 子程序语义：JSR 建 JUMP 边 + fall-through 后继（RET 返回点），RET 无后继

### 4.2 反向污点

- 从 sink 反向回溯，直到 magic entry
- 可控语义：OIS 读 / 入口 this / proxy args / 字段 / 数组 / passthrough
- **反射跳边**：常量类 `getMethod/getDeclaredMethod` 的 invoke 位点视为目标类 public 方法的伪调用者
- **JavaBean 反射跳**：`getReadMethod/getWriteMethod` 模式 → getter 前缀方法目标（万能类型走 wildcard）
- **入口距离调度**：sink 与调用者按入口 BFS 距离升序——预算优先花在高可达成区
- **段级记忆化**：`方法X→入口Y` 结论跨 sink 复用（JDD IOCD 思想）；按 sink×段去重，捷径链
  命中即短路当前回溯（预算留给其他 sink）
- **死胡同缓存截断守卫**：深度/预算截断产生的"无链"结论不写入死胡同缓存
- per-sink 有序 work-stealing（16 worker 自适应）

### 4.3 前向污点

- 粗扫（类级事实）→ 精扫（接口/代理/反射精化）单引擎两轮共享
- **调度**：worklist 按方法键去重（pending 集）+ 可达集边界限定 + 调用图后序处理
  （被调者先——事实沿调用链单遍向下流动，GadgetInspector 技术）
- MODEL 规则消费：`this←argN` 容器投毒 / `return←src` 透传
- origin-guided 分发精度：NEW→精确类、FieldRead→声明类型
- **数组元素流**：AASTORE 存污点值 → 数组值污点（param/field 粒度）→ 传参/存字段后 AALOAD 读出可控
- **lambda 分发**：接口调用的 receiver 为 invokedynamic 结果时，沿 LAMBDA 边到实现方法
  （实参槽位按「捕获前缀 + 接口实参序数」映射）
- **并发与确定性**：事实表/死胡同缓存为 ConcurrentHashMap、队列为 ConcurrentLinkedQueue、
  计数为 LongAdder/AtomicLong；环守卫按探索私有（参数传递）；截断产生的 null 不写死胡同缓存
  （按帧判定）；事实替换按「链长 + 跳序列规范形」全序取最小——结果与处理顺序无关

### 4.4 入口闭包

- 从 magic entry + OIS 宿主 BFS
- DISPATCH_CAP 超限展开；接口分发做传递子类型展开（implementers 不穿透实现类的子类，
  展开补齐该缺口；JDK 接口维持声明态以防图扩散）
- 反射跳展开 + JavaBean wildcard 直接种子
- **框架反射供给门**：source 规则声明的框架入口类派生包前缀；仅当 Method.invoke /
  JavaBean 反射位点宿主于框架包内时，应用类的 public 非静态方法才入闭包——包前缀来自
  规则数据，引擎零硬编码
- 距离表供调度使用

### 4.5 链组装扩展：源宿主容器触发桥

方法 M 体内含反序列化源调用（OIS readObject/readUnshared 或任一 `bridge: deserialize` 框架源，
如 Kryo.readClassAndObject / fastjson JSON.parse）时，M 是反序列化源宿主——框架的容器/bean
反序列化机制会以攻击者数据回调元素 hashCode/equals/compareTo。组装器将每个源宿主与全部
trigger-entry 后段链（含公开 gadget 片段）组装成完整攻击路径，机制桥接跳标注框架入口
（如 `Kryo.readClassAndObject`）。宿主排除 JDK 运行时包（java/javax/sun/com.sun/jdk 等，
其 readObject 体是容器触发机制本身）与源框架同包的管线内部调用。合成链带
`pattern:src-container-trigger` 注记；其入口参数是攻击者载荷，不进子进程探针，改由
**段归因**继承证据：内段链（桥接跳目标入口 + 同 sink）被子进程 CONFIRMED 时，完整链标注
`verify:segment-confirmed` 并获得证据加分，排序紧随 CONFIRMED 链。

SafeConfig 布尔求值：`safe-config` 声明可带 `safe-value`（如 Kryo
`setRegistrationRequired` 的安全值为 true）——抑制仅在调用点实参常量等于安全值时生效，
`setRegistrationRequired(false)`（关闭安全模式）不再被误判为已加固。

### 4.5 校准

- Validator 五层：PASM 可行性 / 类型流（非 final 无共同子类即拒） / 序列化可行性 / equals 卫式降级 / 约束图矛盾
- catch 可达性守卫：CCE 类型安全 cast / 受检反射必成功 / 确定性运行时异常无可抛源
- 深链结构门：动态分派跳 >14 且字段流 <17% 剪
- Pruner 软预算：前 8 家族保留，高证据溢出链 DEGRADED
- 四级判定：FEASIBLE / DEGRADED(reason) / NOT_FEASIBLE
- SafeConfig 布尔求值：调用点实参常量等于 `safe-value` 才抑制（setRegistrationRequired(false) 不算加固）

### 4.6 动态验证（子进程链级）

自动执行，流程：

1. **候选选择**：危险 sink 类别加权（JNDI/命令执行/字节码加载/反射/网络/文件）之上叠加
   结构证据分值降序，同一入口类最多 2 条——预算有限时优先消耗在高价值链；
   预算可配置（`--verify-budget N`，默认 20）；TIMEOUT/UNTESTABLE 的链自动重试一次
2. **链级探针**（`ChainVerifyProbe`）：解析链的字段流转跳，自底向上反射实例化并按字段链接成
   完整对象图（含父类字段填充），再触发入口
3. **触发忠实模式**：入口按真实反序列化触发路径触发——hashCode 入口经 `HashMap.put`、
   compareTo/compare 入口经 `TreeSet.add`、equals 入口经非空 `List.contains`、
   readObject 族经序列化-反序列化往返（SERIAL）、代理入口经 `Proxy.newProxyInstance`（PROXY）、
   其余直接调用（DIRECT）——触发语义与链组装的 TRIGGER 桥一致
4. **集合布局构造**：字段链接时，Map/Set/List 类型的字段按声明类型实例化，并把链接目标
   放入 key/元素位——后段入口对象经容器 key 槽进入对象图，容器反序列化时触发其 hashCode/equals/compareTo
5. **sink canary 插桩判定**（`SinkCanaryAgent`，-javaagent 自挂载 + ASM 注入）：
   每条链的子 JVM 启动时把本链 sink 方法入口改写为门卫调用 `SinkCanaryGate.hit(spec)`——
   门卫检查调用栈存在链入口帧才抛 `SinkReachedError`（Error 语义穿透 gadget 的
   `catch(Exception)`），否则放行（JVM 自身与探针基础设施对
   `Constructor.newInstance`/`URL.openConnection`/`Class.forName` 等通用方法的调用不受影响）。
   java.base 核心 sink（如 `Method.invoke`）经 `retransformClasses` 补插桩，标记类经最小
   bootstrap jar 挂载。命中判定：canary 标记 > 栈帧级全等匹配（sink 类名 + 方法名，含 cause
   链），均要求入口帧在场；SINK_TRIGGERED（真到达 sink）> EXECUTED（入口真实调用且正常返回）
   > PARTIAL_PATH（中途异常，链降级保留）；探针 FAILED 为弱否定证据（降级，不否决）。
   canary 命中的 sink 真实方法体不执行——exec/defineClass/connect 类危险副作用被天然解除
6. **子进程隔离**：fork-per-chain（静态状态不跨链污染）；沙箱参数——隔离工作目录与 tmpdir、
   内存上限、headless；classpath 含目标 jar 与全部 `--deps`；fat jar/WAR 惰性展开
   BOOT-INF/WEB-INF 的 classes 与嵌套依赖 jar 供探针解析；先 waitFor 超时再读输出
7. **构造可行性报告**：不可构造的入口类（抽象/无无参构造/不在类路径）按原因类别聚合输出到日志

已知边界：动态验证的入口触发基于 Java 序列化语义（OIS/TRIGGER 桥）；以框架解析为入口的链
（fastjson autoType、Kryo Input、Hutool 二次反序列化等）静态可发现、动态验证覆盖其
gadget 中段（hashCode/equals/readObject 段），框架入口段为后续触发模式扩展方向。

## 5. 规则系统

5 种类型（sink / magic-entry / source / model / chain-fragment），全在 YAML。

- sink：owner/name/descriptor 匹配 + 层次命中
- magic-entry：方法匹配 + implements + `access: private` 过滤
- source：框架入口 + `safe-config` 声明块（偏移序抑制）
- model：声明式污点透传（actions）
- chain-fragment：声明式已知链（entryClass/hops/sinkOwner，后缀匹配支持 repackaged）

装载校验：未知 kind / 缺失 id / 重复 id / 缺失 match 均报错。

## 6. 前端

- fat jar（BOOT-INF）+ WAR（WEB-INF）嵌套 jar 递归（深度 4，条目数与单条目大小双上限）
- 装载顺序 target → deps → JDK；应用类优先，JDK 类不遮蔽
- label 引用缺失即失败（不静默假边）
- 方法首行号进事实模型（`MethodInfo.entryLine`，SARIF 定位用）
- `--jdk-home`：Java 8 读 rt.jar，Java 9+ URLClassLoader 挂载目标 jrt-fs.jar

## 7. 输出

CSV 四表 + SARIF 2.1.0（driver.rules 声明、severity→level 映射、region.startLine、
partialFingerprints）+ JSON/HTML/Markdown。CSV 流式写出（大语料不整表驻留内存）。
diff 子命令按 RFC 4180 解析、链身份键与组序号无关。

## 8. 基准

Gleipner evaluator（`benchmark/Gleipner/run-gleipner.sh`，本地不入库）：

- 链覆盖 106/122，误报块 22/47（evaluator 块计数 TP=148 / FP=22）
- 能力面：multipath 10/10、depth 18/20、polymorphism 20/20
- 9 语料回归全通过（demo/demo2/Unictf/java-quote/Remo/warmup/javamix/n1cat/qiao）
