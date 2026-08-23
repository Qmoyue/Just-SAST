# AGENTS.md

面向在此仓库工作的 AI 编程代理的开发规范。

## 项目

Just：轻量字节码 SAST，挖掘 Java 反序列化 gadget 利用链。
覆盖原生 OIS + 12 替代框架。单 CLI JAR，六格式输出。

## 命令

```bash
mvn package -DskipTests                # 构建 target/just-sast-0.2.0.jar
mvn test                               # 语义/契约/端到端回归
java -jar target/just-sast-0.2.0.jar scan --jar x.jar
```

双层回归：`mvn test` + Gleipner evaluator（本地 `benchmark/Gleipner/run-gleipner.sh`，不入库）。

## 知识源

12 个内置引擎，按职责分包（不做 ksN 编号）。
同阶段执行序由 `KnowledgeSource.priority()` 声明（小者先）。

## 开发规范

1. ASM 仅在 frontend；知识源互不直接调用；分层单向。
2. 知识源可扩展：实现 `KnowledgeSource`（phase/priority/interests）+ ServiceLoader 注册。
3. 规则做数据，引擎做语义——新增攻击面改 YAML。
4. 禁止 benchmark 过拟合。
5. record/sealed、少状态少抽象；日志走 stderr。
6. 新增/修改功能后先 `mvn test`，再 Gleipner 回归。

## 仓库约定

- `benchmark/` 与 `docs/development.md` 仅存本地，不得提交。
- 规则文件：`src/main/resources/rules/default-rules.yaml`。
- 每条链携带 rule_id，假链可归因到规则。
