# Just 需求

本文是 Just 的公开产品合同。Just 面向 Java JAR、WAR、Spring Boot fat JAR 和 class 目录，提供可审计、static-only 的反序列化链分析。

## 运行环境

- Just 使用 JDK 17 运行。
- `--jdk-home` 指向被分析目标的 JDK/JRE 字节码；目标代码不会被启动。
- CLI 失败必须有明确错误和非零退出状态；内部异常不能被转换为空报告。

## 输入合同

支持根 class、普通 JAR/WAR、Spring Boot fat JAR、class 目录、准确 POM、显式依赖目录和目标 JDK。

输入准备必须记录逻辑制品、归档路径、SHA-256、artifact role、来源和可选精确坐标。必须识别 manifest、classpath/layers metadata 和 `META-INF/maven/**/pom.properties`；不能按类名猜坐标或版本。

无 POM 的自包含 fat JAR 必须支持 `--offline` 扫描。nested JAR 直接读取，不创建仓库 `tmp` 解压树；缺失类型、重复 class、版本歧义和未知 API 必须保留在 coverage/limits。不可解析归档必须明确失败。

`--offline` 不联网、不读取用户 Maven 配置、不生成临时 POM；online、dependency resolution、analysis、report 和 total 的耗时彼此区分。

## 分析合同

### Component

报告可复用的入口、callback、bridge、terminal 和对象/控制条件，但不能把 component capability 称为应用漏洞。

### Application

只有目标制品定义的 `public static void main(String[])` 可以成为应用入口。依赖 JAR 的同名 `main`、孤立方法和普通 public 方法不是入口。应用模式必须证明：

```text
真实 entry → 实际 site/input → typed bridge/callback → terminal/impact
```

没有真实入口或 site 时返回 `NO_APPLICATION_ENTRY`，不通过全局反向 sink 搜索制造候选；这不等价于“安全”。

### 通用语义

API 规则按 owner、名称、调用种类和准确 descriptor 匹配。LambdaMetafactory、ObjectFactory、Reference、JDBC/JAAS、JNDI、Proxy、DirContext 和 Hessian 的连接必须保留 slot、descriptor、identity、控制条件和 artifact provenance。

同名不同对象、类型或 descriptor 不一致、接口没有 concrete implementer、依赖缺失或预算耗尽时只能输出 `PARTIAL`/`UNKNOWN` 与原因，不得猜测或静默降级。

## 报告合同

默认输出为：

```text
<output>/report.json
<output>/report.md
<output>/evidence/
<output>/meta/
```

`report.json` 与 `report.md` 必须来自同一个 `JUST-REPORT-V2` projection。主报告保留结果、coverage、limits、provenance 以及 entry/site/bridge/impact 图；完整 descriptor、offset、对象关系和诊断留在 evidence/meta。

报告不得生成空 `findings/` 目录，不得输出 `is_partial`、`partial_reason`、`chain_partial`、`execution_status`、动态验证字段、攻击字节流或 `RCE_CONFIRMED`。

状态含义：

| 状态 | 含义 |
| --- | --- |
| `COMPLETE` | 静态必要跳点和约束均已证明，不表示目标代码执行 |
| `PARTIAL` | 主链有静态证据，但存在已命名缺口 |
| `UNKNOWN` | 信息不足，不能支持或否定连接 |
| `NO_FINDINGS` | 当前输入没有可导出的静态 finding |
| `FAILED` | 输入、配置或内部错误阻止分析 |

## 安全与质量门槛

Just 不加载、初始化、构造或反射调用目标类，不读取或执行攻击反序列化流，不启动目标服务/进程，不调用 payload/callback，也不生成可投递攻击字节流。

发布前必须通过 Maven 测试、两种模式 static smoke、无 POM/offline fixture、报告 schema 校验、Apache 正负例和固定语料回归。每个回归结论都必须以实际输入字节、来源 hash 和可审计 typed evidence 为依据；WP、题名、路径、digest 和答案不能进入生产规则。

## 许可证与发布

项目使用 GPLv3-only；第三方依赖和许可证见 [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md)。发布资产至少包含 shaded JAR、SHA-256、LICENSE 和第三方声明；发布构建必须从已验证的 Git ref 生成，并通过仓库 GitHub Actions 的 CI/Release workflow。
