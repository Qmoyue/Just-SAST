# Third-Party Notices

Just 以 GPLv3 发布，分发物（shaded JAR）捆绑以下第三方依赖：

| 依赖组 | 版本 | 许可证 | GPLv3 兼容性 |
|---|---|---|---|
| OW2 ASM / ASM Tree / ASM Commons | 9.8 | BSD-3-Clause | 兼容 |
| picocli | 4.7.7 | Apache-2.0 | 兼容 |
| SnakeYAML | 2.4 | Apache-2.0 | 兼容 |
| Apache Maven Model / Model Builder / Resolver Provider | 3.9.16 | Apache-2.0 | 兼容 |
| Maven Resolver API / SPI / Util / Impl / Named Locks / Connector Basic / File / HTTP | 1.9.27 | Apache-2.0 | 兼容 |
| Plexus Utils / Plexus Interpolation | 3.6.1 / 1.29 | Apache-2.0 | 兼容 |
| Eclipse Sisu Inject | 1.0.0 | EPL-1.0 | 兼容 |
| javax.inject | 1 | Apache-2.0 | 兼容 |
| SLF4J API / JCL bridge | 1.7.36 | MIT | 兼容 |
| Gson | 2.13.2 | Apache-2.0 | 兼容 |
| Error Prone Annotations | 2.41.0 | Apache-2.0 | 兼容 |
| Apache HttpClient / HttpCore | 4.5.14 / 4.4.16 | Apache-2.0 | 兼容 |
| Commons Codec | 1.21.0 | Apache-2.0 | 兼容 |

测试作用域依赖（不随产物分发）：JUnit Jupiter 5.10.2（EPL-2.0）。

版本与运行时作用域按 Maven dependency tree（`mvn dependency:tree -Dscope=runtime`）核对；
若升级依赖，必须同步复核各 artifact 的许可证/NOTICE 文本和发布资产。
