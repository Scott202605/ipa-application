# IPAd Manager 与 SDK 能力矩阵

| 能力 | 状态 | 安装验收范围 |
|---|---|---|
| SDK 初始化/反初始化 | Available | 无硬件 smoke test 与发布门禁 |
| 信息查询入口 | Environment-dependent | 接口、ABI 和调用链；真实结果依赖 eUICC |
| 通知处理 | Available | SDK 回归测试 |
| Fallback | Environment-dependent | 完整结果依赖真实 Profile 环境 |
| Emergency Profile | Environment-dependent | 完整结果依赖真实 Profile 环境 |
| HTTP/MQTT/LwM2M | Environment-dependent | TLS 策略和入口；结果依赖远端服务 |
| PC/SC、AT 串口 | Environment-dependent | 依赖和配置探测；设备操作需硬件验收 |
| Manager Profile 下载 | Not implemented | 返回 `eNotImpl` |
| Manager Profile 启用 | Not implemented | 返回 `eNotImpl` |
| Manager Profile 禁用 | Not implemented | 返回 `eNotImpl` |
| Manager Profile 删除 | Not implemented | 返回 `eNotImpl` |

安装成功不等于外部硬件或服务已经就绪，也不会把 `eNotImpl` 能力误报为可用。
