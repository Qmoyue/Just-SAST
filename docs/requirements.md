# Just — 需求文档

## 1. 概述

轻量 Java SAST：对 JAR/WAR 挖掘反序列化 gadget 链。覆盖原生 OIS + 12+ 替代框架。

交付：单 CLI JAR，六格式输出，`--jdk-home` 精确匹配。

## 2. 功能需求

| 编号 | 需求 |
|---|---|
| FR1 | 输入：JAR/WAR/目录 + `--deps`；嵌套 jar 递归（深度 4） |
| FR2 | ASM 解析为自研 model（不依赖 ASM 传播到分析层） |
| FR3 | 轻量代码图：CHA 调用图 + 可见性剪枝 + 构建后冻结 |
| FR4 | 类层次：Serializable 判定 + 懒加载 + 增量缓存失效 |
| FR5 | 调用图：传递子类型分发（ClassHierarchy 记忆化闭包，引擎侧展开与调用图同源）+ 反射跳边 + JavaBean 跳 + DISPATCH_CAP 闭包展开；JSR/RET 子程序语义（JSR 有 fall-through 后继，RET 无后继） |
| FR6 | 反向污点：sink 回溯 + 入口距离调度 + per-sink 并行 + 段级记忆化（按 sink×段去重，捷径短路）；死胡同记忆化排除深度/预算截断结论 |
| FR7 | 前向污点：粗扫+精扫单引擎 + MODEL 规则消费 + origin-guided 精度 + 数组元素流（AASTORE/AALOAD 经 param/field 粒度跨方法）+ lambda 经函数式接口分发（receiver 为 indy 结果时沿 LAMBDA 边到实现方法）+ 调用图后序 worklist（去重 + 可达集限定） |
| FR8 | OIS 回调：resolveClass/resolveProxyClass + readUnshared 双起跳 |
| FR9 | 框架桥接：12+ marshaller + safe-config 偏移序抑制 |
| FR10 | 对象图扩散：字段类型含数组 + readResolve 重根 |
| FR11 | 片段合成：chain-fragment 规则（后缀匹配） |
| FR12 | 语义链组装：INVOKE/TRIGGER/TEMPLATE/DESER 四桥（TRIGGER 桥带 key/元素槽位类型校验：有序容器 TreeMap/TreeSet/PriorityQueue 要求后段入口类 Comparable） |
| FR13 | 链校验：PASM + 类型流（非 final 参与）+ 序列化 + 约束图矛盾 + catch 可达性守卫 |
| FR14 | 链剪枝：触发上下文 + 深链结构门 + 软预算机制去重 |
| FR15 | 模式识别：集合包含判定 + patterns 列 + 证据加分 |
| FR16 | 动态验证：反射构造可行性 + 子进程链级验证（对象图构造、入口类去重 ≤2、预算 `--verify-budget` 可配置默认 20、失败重试一次）。触发忠实模式：hashCode 经 HashMap.put、compareTo 经 TreeSet.add、equals 经 List.contains、readObject 族经序列化往返。集合布局构造：Map/Set/List 字段按声明类型实例化并放入链接目标。判定：栈帧级精确匹配；FAILED 为弱否定证据（降级不否决）。子进程隔离：fork-per-chain + 隔离工作目录/tmpdir + 内存上限；classpath 含目标 jar + 全部 `--deps`。不可构造类按原因类别聚合报告。`--no-verify` 可关闭；验证子进程以当前用户权限真实执行入口方法，不可信工件应在隔离环境扫描 |
| FR17 | 规则系统：5 种类型改 YAML 零代码；装载校验（未知 kind/缺失 id/重复 id/缺 match 均报错） |
| FR18 | 输出：CSV 四表（流式写出）+ SARIF（driver.rules/level 映射/startLine/partialFingerprints）+ JSON/HTML/Markdown；CONFIRMED 链置顶 |
| FR19 | CLI：scan + diff 子命令；退出码 0/2/3。diff 按 RFC4180 解析（表头驱动列定位），链身份键与组序号无关；findings.csv 缺失时报错退出 2 |
| FR20 | JDK 版本：major version 提取；--jdk-home Java 8/9+ 真挂载 |
| FR21 | 并行：ANALYSIS 并行派发 + backward 16 worker。并发契约：跨线程共享的可变状态为并发容器或参数传递；探索期环守卫按探索私有 |
| FR22 | 阶段内 priority 显式排序；事件跨阶段延迟投递 |

## 3. 非功能

| 编号 | 需求 |
|---|---|
| NFR1 | 运行时依赖仅 ASM（BSD-3）/picocli（Apache-2.0）/SnakeYAML（Apache-2.0）——全部 GPLv3 兼容 |
| NFR2 | 内存可控：4GB 堆 <1 万类 |
| NFR3 | ASM 仅 frontend；知识源互不直接调用 |
| NFR4 | ServiceLoader 注册可扩展 |
| NFR5 | worker 自适应核数（≤16） |
| NFR6 | 不得 benchmark 特判 |
| NFR7 | 双层回归：`mvn test` + Gleipner evaluator |
| NFR8 | 扫描确定性：同一输入在预算内多次扫描输出一致（事实替换按「链长 + 跳序列规范形」全序取最小） |
| NFR9 | 工具自身不引入反序列化攻击面：不使用原生 ObjectInputStream 读取任何工作目录/旁车文件；无跨扫描持久化缓存 |

## 4. 验收

| 项 | 标准 |
|---|---|
| Gleipner | 链覆盖 TP ≥100, FP ≤25（当前 106/22；evaluator 块计数 148/22） |
| 语料 | 9 语料锚点全过（demo/demo2/Unictf/java-quote/Remo/warmup/javamix/n1cat/qiao） |
| 测试 | 70 全绿 |
| 耗时 | 典型 Spring Boot 应用（~11000 类）60-90s（177 条规则全量） |
| 大语料 | 4 万+ 类语料默认堆可完成 |
