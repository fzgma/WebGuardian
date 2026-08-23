# WebGuardian 网站安全检测工具

## 🚀立即体验

无需本地部署，点击链接即可使用：

 ### [WebGuardian Streamlit](https://web-guardian.streamlit.app)

注意：请在合法授权范围内使用。检测结果会受到网络环境影响，结果仅供参考

## 项目说明

WebGuardian 是一个基于 Python 和 Streamlit 开发的网站基础安全检测工具。输入目标网站地址后，工具会执行可配置的基础站点检测、DNS 安全检查和页面级安全检查，并输出安全评分、安全等级、风险提示、检测耗时、本次扫描过程中的基础可用性指标和原始检测数据。

项目定位为轻量的安全基线检查工具，不替代专业漏洞扫描、渗透测试或持续安全监测。

当前仅支持 `http` 和 `https` 协议；`file`、`ftp`、`ssh` 等非 HTTP 协议会被直接拒绝。

## 一、主要功能

### 1. HTTPS 检测

检测最终访问地址是否走 HTTPS。输入地址发生跳转时，以最终响应地址为准。

### 2. SSL/TLS 证书检测

检测 HTTPS 连接是否有效，并显示证书剩余有效天数。

### 网站可用性观测

在本次正式请求上记录 `DNS` 解析、`TCP` 连接、`TLS` 握手、`TTFB` 和发送/接收总量，并在结果页的折叠区展示，便于查看基础响应情况。不进行并发请求或压力测试。

### 3. HTTP 安全响应头检测

检查常见安全头是否存在，当前重点关注 `CSP`、`HSTS`、`X-Frame-Options` 等项，用于降低 XSS、点击劫持和 MIME 嗅探风险。

### 4. DNS 安全检测

检查域名的 `SPF`、`DMARC` 和 `CAA` 记录，帮助发现邮件伪造和证书签发范围过宽等问题。

### 5. HTTP 方法检测

先发 `OPTIONS` 请求，再结合 `Allow` 和 `Access-Control-Allow-Methods` 判断服务器暴露了哪些方法，同时单独检测 `TRACE` 是否可用。`PUT`、`DELETE`、`PATCH` 只做暴露推断，不做副作用实测。

### 6. 敏感路径检测

检查常见后台、备份、调试和接口文档路径，如 `/admin`、`/docs`、`/api/docs`、`/swagger`、`/phpinfo.php` 等。命中路径不等于漏洞，但通常说明暴露面偏大。

### 7. 暴露信息检测

检查响应头和页面源码中的高信号暴露项，包括服务器/框架标识、版本特征，以及 `generator`、`application-name`、`og:site_name`、`author` 等重点 `meta` 字段。

### 8. 页面级检查

页面级检查从首页开始轻量抓取，只跟进同源 HTML 链接，并限制抓取页数和深度。可选项包括混合内容、不安全表单、Cookie 安全属性、重定向链、页面响应头、页面源码暴露信息，以及 `robots.txt / sitemap.xml` 暴露面分析。

### 9. 扫描模式与进度

界面提供标准、快速、深度和自定义四种模式。修改任一选项后会自动切换为自定义模式，输入 URL 后可按 Enter 直接开始扫描，扫描中也可以随时停止。

进度条按当前启用项动态计算，请求失败、非 HTML 页面或跨源跳转导致的跳过项也会补足进度。

## 二、评分与等级

总分按已启用的基础检测项归一化为 100 分。页面级安全检查用于暴露页面风险，当前不直接计入总评分。

| 检测项 | 最高分 | 得分条件 |
|---|---:|---|
| HTTPS | 10 | 最终地址使用 HTTPS |
| SSL/TLS | 20 | 证书有效、有效期、协议与套件、证书链完整性 |
| DNS 安全检测 | 15 | SPF、DMARC、CAA 越完整，得分越高 |
| HTTP 安全响应头 | 30 | 常见安全头完整度，当前重点关注 CSP、HSTS、X-Frame-Options |
| 暴露信息检测 | 10 | 未发现响应头和 meta 暴露项 |
| HTTP 方法检测 | 5 | 未发现 TRACE 可用或其他高风险方法暴露 |
| 敏感路径 | 10 | 未发现内置敏感路径 |

| 分数范围 | 等级 |
|---|---|
| 85 - 100 | A级 |
| 70 - 84 | B级 |
| 0 - 69 | C级 |

关闭某项基础检测后，该项不会计入可得分总分。

## 三、项目结构

```text
main.py                    # 直接启动 Streamlit 应用
app.py                     # 页面流程、URL 表单和扫描调用
scanner/
  options.py               # 扫描配置模型
  scanner.py               # 主扫描编排和 ScanContext
  basescan/
    __init__.py            # 基础站点扫描入口
    base_checks.py         # HTTPS、安全头、暴露信息、HTTP 方法、敏感路径
    tls.py                 # TLS/SSL 证书与配置检测
    dns.py                 # SPF、DMARC、CAA 检测
  pagecheck/
    page_scan.py           # 同源页面抓取与检查编排
    page_checks.py         # HTML 解析及页面安全检查规则
    page_results.py        # 页面发现、风险统计和结果聚合
    sitecheck/             # robots.txt / sitemap.xml 暴露面分析
utils/
  control.py               # 扫描中断信号
  net.py                   # 请求会话、URL 校验和地址规范化
  timer.py                 # 扫描耗时统计
ui/
  result/
    view.py                 # 扫描结果展示
scanner/basescan/
  availability.py          # 单次正式请求的可用性指标采集
runtime/
  scan_progress.py          # 按工作量计算扫描进度
  models.py                # 运行状态和运行时快照
  runtime.py               # 后台执行、停止控制和运行状态
  view.py                  # 运行状态和结果展示
  errors.py                # 错误归类与友好提示
result_model/
  models.py                # 扫描领域结果模型
  composer.py              # 后端结果包装和合成
  security_score.py        # 安全评分与等级规则
ui/
  scan_config.py            # 扫描模式、配置控件和配置校验
requirements.txt           # 运行依赖
```

## 四、安装与运行

### 1. Python 版本要求

最低要求：**Python3.10**

项目代码使用了联合类型注解等语法，低于 3.10 的解释器不兼容。

建议使用 ：**Python 3.13**。

### 2. 创建虚拟环境

Windows PowerShell：

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS 或 Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```


### 4. 启动应用

在项目根目录执行：

```powershell
py main.py
```
或
```
streamlit run app.py
```

`main.py` 已包含 Streamlit 启动逻辑。也可以用传统方式`streamlit run `启动成功后，终端会显示本地访问地址，默认通常为 `http://localhost:8501`。

### 5. 使用 Docker 镜像

如果希望使用Docker：

```bash
docker pull ghcr.io/fzgma/webguardian:latest
docker run --rm -p 8501:8501 ghcr.io/fzgma/webguardian:latest
```

如果镜像已经在本地，也可以直接运行：

```bash
docker run --rm -p 8501:8501 ghcr.io/fzgma/webguardian:latest
```

启动后访问 `http://localhost:8501` 即可。

## 五、使用方式

1. 选择预设扫描模式，或进入自定义模式。
2. 需要页面级检查时，启用该开关并至少选择一个页面子项。
3. 输入网站地址，例如 `https://example.com`。
4. 如果使用 Docker 运行，先启动容器，再在浏览器访问容器暴露的地址。
5. 按 Enter 或点击“开始检测”。
6. 查看安全评分、基础检测结果、网站可用性、页面级风险、过程提示和原始 JSON 数据，必要时可在检测中停止任务。

首次启动后的第一次扫描可能因为 Streamlit、Python 依赖和前端组件的冷启动与预热而耗时较长；同一进程后续扫描通常会更快。

如果输入地址无效，界面会直接提示具体原因，不会开始扫描。

若所有检测项均关闭，或页面级检查未选择任何子项，应用会在开始扫描前提示修正配置。


## 六、结果架构

扫描结果采用“模块小结果 -> 统一大结果 -> 展示模型”的分层结构：

1. `scanner/scanner.py` 创建一次扫描的 `ScanContext`，保存目标地址、会话、扫描配置、进度和停止信号等运行态信息。
2. HTTPS、网站可用性、TLS、DNS、安全响应头、HTTP 方法、敏感路径、信息泄露和页面扫描分别生成独立的 section result。
3. `result_model/composer.py` 统一包装和合成结果，聚合各模块的 `warnings`、`findings` 和错误，并生成评分、等级、耗时和页面扫描摘要。
4. `ui/result/view.py` 通过 `result_model/composer.py` 将扫描结果转换为展示层模型，再按模块渲染，网站可用性会在基础信息下方折叠展示。

成功扫描结果的顶层结构如下：

```text
{
  "target": {...},    # 输入地址、规范化地址、主机和解析 IP
  "checks": {...},    # 各检测模块的独立结果
  "summary": {...},   # 评分、等级、耗时和页面扫描摘要
  "errors": [...],    # 检测过程中的错误和警告
  "warnings": [...]
}
```


## 七、注意事项

1. 仅检测自己拥有或已经获得明确授权的网站。
2. 本工具不尝试绕过认证、WAF、访问控制或其他安全机制。
3. 检测结果会受到网络环境、代理、CDN、WAF、目标站点配置和证书链的影响。
4. 敏感路径检查仅使用内置的有限路径列表，路径存在不代表可被未授权访问。
5. 页面级检查受最大页数和最大深度限制，不能代表整个站点的完整审计结果。
6. `0.0.0.0`、`::` 以及 `224.0.0.0-255.255.255.255` 这类地址会被当作无效输入。

## 八、法律声明与使用许可

### 开源许可

WebGuardian 采用 **GNU General Public License v3.0（GPL-3.0）** 开源协议。

你可以根据 GPL-3.0 的条款自由使用、学习、修改和分发本项目。

完整许可证内容请参阅项目中的 `LICENSE` 文件。

---

### 依赖库许可

本项目当前使用的第三方库包括：

- `streamlit`：**Apache-2.0**
- `requests`：**Apache-2.0**
- `cryptography`：**Apache-2.0**
- `beautifulsoup4`：**MIT License**
- `dnspython`：**ISC**

 ### 上述依赖库均为开源软件。具体条款以各项目官方仓库、随包附带的许可文件为准。
---

### 使用须知

WebGuardian 是一个轻量级网站安全检测工具，主要用于：

- 学习网站安全基础知识；
- 检查自己网站的基础安全配置；
- 辅助进行简单的安全排查。

本工具不能替代：

- 专业漏洞扫描工具；
- 渗透测试；
- 安全评估服务；
- 企业级安全监控系统。

请勿将本工具用于未经授权的网站、服务器或其他网络资源检测。

用户在使用前应确保已经获得目标系统所有者或相关授权方的许可。

检测结果仅供参考，未发现问题不代表目标系统不存在安全风险。

---

### 免责声明

本工具按照“现状”（AS IS）提供。

作者不保证：

- 检测结果完全准确；
- 能发现所有安全问题；
- 工具适用于所有环境。

因使用、修改或误用本工具产生的风险、损失或法律责任，由使用者自行承担。
