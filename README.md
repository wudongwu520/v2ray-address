# 节点地区自动标注工具

一款基于Python的代理节点处理工具，能够自动解析各类代理节点、查询服务器地理位置，并为节点添加地区标注，方便用户快速识别节点来源。

## 功能亮点

- **多协议支持**：兼容13+种主流代理协议（详见下方支持列表）
- **智能编码识别**：自动检测文件编码（utf-8、gbk、latin-1等），避免乱码问题
- **批量高效处理**：支持并发处理大量节点，节省时间
- **详细统计报告**：生成节点处理报告，包含协议分布、地区分布等数据
- **地理位置精准查询**：集成多API备份，提高IP定位成功率

## 支持协议

| 协议类型       | 协议标识                  |
|----------------|---------------------------|
| 基础代理       | vmess://、ss://、ssr://    |
| 主流加密代理   | vless://、trojan://        |
| 新兴高速协议   | tuic://、hysteria://、hysteria2:// |
| 通用代理       | socks5://、http://、https:// |
| VPN协议        | wireguard://、naive://     |

## 快速开始

### 前提条件

- Python 3.6+ 环境
- 网络连接（用于查询IP地理位置）

### 安装步骤

1. 克隆本仓库或下载代码：
   ```bash
   git clone https://github.com/wudongwu520/v2ray-address.git
   cd v2ray-address

2. 安装依赖库：
bash
pip install -r requirements.txt


如果提示pip命令不存在，尝试：
bash
python -m pip install -r requirements.txt

使用方法
准备一个包含节点的文本文件（如nodes.txt），格式要求：
每行一个节点链接
示例：vmess://abcdefghijklmnopqrstuvwxyz
运行工具：
bash
python v2ray_geo_more_protocols.py 输入文件路径 输出文件路径

示例：
bash
# 处理当前目录下的nodes.txt，输出到result.txt
python v2ray_geo_more_protocols.py nodes.txt result.txt

输出说明
处理完成后，会生成带有地区标注的节点文件（如result.txt），节点格式示例：
vmess://xxx#[美国]
ss://xxx#[日本]
同时控制台会显示详细统计信息：
总处理节点数、成功 / 失败数量
各协议节点分布情况
各国家 / 地区节点数量分布
处理耗时
常见问题
1. 报错 "ModuleNotFoundError: No module named 'xxx'"
解决：缺少依赖库，执行pip install 缺失的库名（如pip install chardet）
2. 节点解码失败（Base64 错误）
原因：节点链接格式错误或包含多余字符（如注释、空格）
解决：检查节点文件，确保每行仅包含纯节点链接，无其他内容
3. 地理位置显示 "未知"
原因：网络问题或 IP 查询 API 暂时不可用
解决：检查网络连接，工具会自动重试并切换备用 API
4. 文件读取乱码
原因：文件编码格式特殊
解决：工具已集成自动编码检测，无需手动处理
许可证
本项目采用 MIT 许可证，详情参见 LICENSE 文件。
贡献
欢迎提交 Issues 或 Pull Request 改进本工具，一起完善功能！  让AI写的我不会写代码

