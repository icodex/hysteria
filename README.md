# ![Hysteria 2](logo.svg)

# 支持对接V2board面板的Hysteria2后端

### 项目说明
本项目基于hysteria官方内核二次开发，添加了从v2b获取节点信息、用户鉴权信息与上报用户流量的功能。
性能方面已经由hysteria2内核作者亲自指导优化过了。

### 面板功能支持
- 用户同步：REST 轮询，面板开启 WebSocket 推送时自动切换（断开自动回退）
- 流量上报：定时提交面板，`base_config.push_interval/pull_interval` 下发的间隔优先生效
- 配置变更：面板修改端口/混淆/带宽后自动重启节点生效
- **speed_limit**：面板 per-user 限速（Mbps，上下行各自限速）实时生效
- **device_limit**：面板 per-user 设备数限制，配合在线设备上报（WS `report.devices` / REST `/alive`）
- 超流量账号：面板推送 delta remove 后立即断开

### 注意事项
- **带宽映射**：面板 `down_mbps` 映射为节点上行（server up）、`up_mbps` 映射为节点下行——与 Xboard-node 官方节点（直映射）相反。面板上下行填相同数值则无差异；不对称时请按本节点语义填写。
- 面板接口兼容 Xboard 与 V2board（obfs / obfs-password 自动适配）。

### TG交流群
欢迎加入交流群 [点击加入](https://t.me/+DcRt8AB2VbI2Yzc1)


### 示例配置
```
v2board:
  apiHost: https://面板地址
  apiKey: 面板节点密钥
  nodeID: 节点ID
tls:
  type: tls
  cert: /etc/hysteria/tls.crt
  key: /etc/hysteria/tls.key
auth:
  type: v2board
trafficStats:
  listen: 127.0.0.1:7653
acl: 
  inline: 
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(127.0.0.0/8)
    - reject(fc00::/7)
```
> 其他配置完全与hysteria文档的一致，可以查看hysteria2官方文档 [点击查看](https://hysteria.network/zh/docs/getting-started/Installation/) 

### 快速启动
```
docker run -itd --restart=always  --network=host \
 -e apiHost=https://example.com \
 -e apiKey=xxxxxxxxxxxxxxxxxxxxx \
 -e domain=hy2.example.com  \
 -e nodeID=1 \
ghcr.io/icodex/hysteria:latest
```
### docker 仓库
```
docker pull ghcr.io/icodex/hysteria:latest
