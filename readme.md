# 一 概述

官方文档: https://sigmahq.io/

Github 链接：https://github.com/SigmaHQ/sigma

Sigma 是一种通用且开放的检测规则格式（SIEM 系统的通用签名格式），可让匹配描述相关的日志事件。规则格式非常灵活，易于编写且适用于任何类型的日志文件。该项目可以直接使用sigma格式进行威胁检测，也可以进行不同 SIEM 系统的格式转换。同时 Sigma 可以通过行为规则生成 ATT&CK Navigator 热力图，直观看到行为模型的覆盖程度

# 二 快速入口

参考官方文档：https://sigmahq.io/docs/guide/getting-started.html

# 三 解析规则

## 3.1 概述

Sigma 由 Python 编写，考虑到公司技术架构以 Java 为主，故自研解析 Sigma Rule

解析代码可参考：https://github.com/confluentinc/confluent-sigma.git

但是 confluent-sigma 代码写得混乱、不支持 1/all of search-identifier-pattern、甚至有些 Bug 等，故代码结构可以借鉴，还是根据官方给出的 Sigma Specs 来重构

官方 Sigma Specs 文档：https://sigmahq.io/sigma-specification/Sigma_specification.html

## 3.2 代码重构

代码仓库链接：https://github.com/tanbingshi666/sigma-parser

## 3.3 支持语句

```
目前只考虑 AND, OR, 1 of selection*, all of selection*, not, () 情况
情况一: condition: selection
情况二: condition: selection1 and selection2
情况三: condition: selection1 or selection2

情况四: 1 of selection*
情况五: all of selection* and select

情况六: condition: not selection
情况七: condition: other and not 1 of selection*

情况八: condition: selection1 and (keywords1 or keywords2)

备注: 建议将 (...) 放在 condition 语句的最后面, 因为从 condition 后面开始往前变量检测 detection 规则, 如果没有，请考虑 condition 整个语句是否受 (...) 影响。后续代码可能优化改造成 DAG 模式, 待开发
```

## 3.4 不支持语句

​	暂时不支持 AGG 模式

# 四 解析输出

​	暂定，目前只完成解析成功与否 (true or false)