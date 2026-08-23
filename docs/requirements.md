# Just — 需求文档

## 1. 概述

轻量 Java SAST：对 JAR/WAR 挖掘反序列化 gadget 链。覆盖原生 OIS + 12 替代框架。

交付：单 CLI JAR，六格式输出，`--jdk-home` 精确匹配。

## 2. 功能需求

| 编号 | 需求 |
|---|---|
| FR1 | 输入：JAR/WAR/目录 + `--deps`；嵌套 jar 递归（深度 4） |
| FR2 | ASM 解析为自研 model（不依赖 ASM 传播到分析层） |
| FR3 | CPG：CHA 调用图 + 可见性剪枝 + 构建后冻结 |
| FR4 | 类层次：Serializable 判定 + 懒加载 + 增量缓存失效 |
| FR5 | 调用图：传递子类型分发 + 反射跳边 + JavaBean 跳 + DISPATCH_CAP 闭包展开 |
| FR6 | 反向污点：sink 回溯 + 入口距离调度 + 段级记忆化 + per-sink 并行 |
| FR7 | 前向污点：粗扫+精扫单引擎 + MODEL 规则消费 + origin-guided 精度 |
| FR8 | OIS 回调：resolveClass/resolveProxyClass + readUnshared 双起跳 |
| FR9 | 框架桥接：12 marshaller + safe-config 偏移序抑制 |
| FR10 | 对象图扩散：字段类型含数组 + readResolve 重根 |
| FR11 | 片段合成：chain-fragment 规则（后缀匹配） |
| FR12 | 语义链组装：INVOKE/TRIGGER/TEMPLATE/DESER 四桥 |
| FR13 | 链校验：PASM + 类型流（非 final 参与）+ 序列化 + 约束图矛盾 + catch 可达性守卫 |
| FR14 | 链剪枝：触发上下文 + 深链结构门 + 软预算机制去重 |
| FR15 | 模式识别：集合包含判定 + patterns 列 + 证据加分 |
| FR16 | 动态验证：反射构造可行性 + 子进程链级验证（对象图构造、入口类去重 ≤2、sink 特异性三级判定） |
| FR17 | 规则系统：5 种类型改 YAML 零代码 |
| FR18 | 输出：CSV 四表（流式写出）+ SARIF + JSON/HTML/Markdown；CONFIRMED 链置顶 |
| FR19 | CLI：scan + diff 子命令；退出码 0/2/3 |
| FR20 | JDK 版本：major version 提取；--jdk-home Java 8/9+ 真挂载 |
| FR21 | 并行：ANALYSIS 并行派发 + backward 16 worker + 精扫 parallelStream |
| FR22 | 阶段内 priority 显式排序 |

## 3. 非功能

| 编号 | 需求 |
|---|---|
| NFR1 | 运行时依赖仅 ASM/picocli/SnakeYAML |
| NFR2 | 内存可控：4GB 堆 <1 万类 |
| NFR3 | ASM 仅 frontend；知识源互不直接调用 |
| NFR4 | ServiceLoader 注册可扩展 |
| NFR5 | worker 自适应核数（≤16） |
| NFR6 | 不得 benchmark 特判 |
| NFR7 | 双层回归：`mvn test` + Gleipner evaluator |

## 4. 验收

| 项 | 标准 |
|---|---|
| Gleipner | 链覆盖 TP ≥100, FP ≤25（当前 106/22） |
| 语料 | 9 语料锚点全过（demo/demo2/Unictf/java-quote/Remo/warmup/javamix/n1cat/qiao） |
| 测试 | 50+ 全绿 |
| 耗时 | demo2 <60s（当前 ~50s） |
| 大语料 | 4 万+ 类语料默认堆可完成（javamix 42260 类验证通过） |
