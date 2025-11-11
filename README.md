# SNMP Trap Webhook Plugin

一个用于监听 SNMP Trap 告警并通过主动消息接口发送到 QQ 群的 LangBot 插件。

## 功能特性

- 🚨 **SNMP Trap 监听**：监听指定端口接收 SNMP Trap 消息
- 📱 **QQ 群通知**：自动转发告警到指定 QQ 群并艾特所有人
- 🔧 **配置灵活**：支持插件配置和环境变量配置
- 🧪 **测试功能**：提供测试告警和接收器测试工具
- 📊 **状态查询**：通过命令查询插件运行状态

## 项目结构

```
SnmpPlugin/
├── main.py                          # 插件主入口
├── manifest.yaml                    # 插件清单文件
├── README.md                        # 项目说明文档
├── test_send_trap.py               # SNMP Trap 测试脚本
├── components/
│   ├── __init__.py
│   ├── commands/                    # 命令组件
│   │   ├── __init__.py
│   │   ├── snmp_status.py          # SNMP 状态查询命令
│   │   └── snmp_status.yaml
│   ├── event_listener/             # 事件监听器
│   │   ├── __init__.py
│   │   ├── default.py              # 主要的事件监听器
│   │   └── default.yaml
│   ├── services/                   # 服务层
│   │   └── snmp_trap_receiver.py   # SNMP Trap 接收服务
│   ├── tools/                      # 工具组件
│   │   ├── __init__.py
│   │   ├── send_test_alert.py      # 发送测试告警工具
│   │   ├── send_test_alert.yaml
│   │   ├── test_snmp_receiver.py   # 测试 SNMP 接收器工具
│   │   └── test_snmp_receiver.yaml
│   └── utils/                      # 工具类
│       ├── __init__.py
│       └── message_helper.py       # 消息发送辅助类
```

## 配置说明

### 1. 插件配置

在 LangBot 管理界面中配置插件：

- **default_group_id**: 默认 QQ 群号（必填）

### 2. 环境变量配置

在 `.env` 文件中设置：

```bash
SNMP_DEFAULT_GROUP_ID=你的实际QQ群号
```

配置优先级：插件配置 > 环境变量 > 默认值

## 使用方法

### 1. 查看插件状态

使用命令查看插件运行状态：
```
!snmp_status
# 或
!status
```

### 2. 发送测试告警

使用工具发送测试告警消息到配置的 QQ 群。

### 3. 测试 SNMP 接收器

使用测试工具检查 SNMP Trap 接收器是否正常工作。

### 4. 发送 SNMP Trap

使用提供的测试脚本发送 SNMP Trap：

```bash
python test_send_trap.py
```

或使用系统命令：

```bash
# Windows
snmptrap -v 2c -c public localhost:1162 '' .1.3.6.1.4.1.9 1

# Linux
snmptrap -v 2c -c public localhost:1162 '' .1.3.6.1.4.1.9 1
```

## 技术特点

### 代码优化

本次优化主要解决了以下问题：

1. **消除重复代码**：
   - 提取了公共的消息发送逻辑到 `MessageHelper` 类
   - 统一了配置读取逻辑
   - 简化了消息格式化功能

2. **简化组件结构**：
   - 删除了功能重复的工具文件
   - 保留了核心的测试和告警功能
   - 优化了代码组织结构

3. **增强可维护性**：
   - 统一了错误处理
   - 改进了日志输出
   - 提高了代码复用性

### 架构改进

- **模块化设计**：将公共功能抽取到工具类中
- **单一职责**：每个组件专注于特定功能
- **配置集中**：统一管理插件配置读取
- **错误处理**：增强异常处理和日志记录

## 依赖项

- Python 3.7+
- LangBot 框架
- 无额外第三方依赖

## 注意事项

1. **端口权限**：SNMP Trap 默认监听 1162 端口（避免权限问题）
2. **网络配置**：确保防火墙允许相应端口的 UDP 流量
3. **QQ 机器人**：需要配置可用的 QQ 机器人实例
4. **权限要求**：插件需要发送消息和@全体成员的权限

## 更新日志

### v0.1.0 (优化版本)
- ✅ 重构代码结构，消除重复代码
- ✅ 新增 `MessageHelper` 工具类
- ✅ 简化配置读取逻辑
- ✅ 删除冗余工具文件
- ✅ 优化错误处理和日志
- ✅ 改进命令响应内容
- ✅ 增强测试功能
