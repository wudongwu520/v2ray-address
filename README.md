# V2Ray节点地区标注工具

一款自动解析代理节点、查询地区并添加标注的工具，支持多种主流协议（vmess、ss、vless、trojan等）。

## 功能特点
- 自动识别节点协议（支持13+种常用协议）
- 解析节点地址并查询地理位置
- 批量处理节点文件，添加地区标注（如 `[美国]`）
- 自动检测文件编码，避免乱码问题
- 生成处理报告（包含节点数量、地区分布等统计）

## 支持协议
- 基础协议：vmess、ss（Shadowsocks）、ssr（ShadowsocksR）
- 主流协议：vless、trojan、tuic
- 新兴协议：hysteria、hysteria2、wireguard、naive
- 通用代理：socks5、http、https

## 安装步骤

### 1. 下载代码
```bash
# 克隆仓库（发布后使用）
git clone https://github.com/你的用户名/仓库名.git
cd 仓库名

