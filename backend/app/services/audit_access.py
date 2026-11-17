"""审计授权上下文：从请求中解析当前用户组、授权方式与角色。

页面、明细接口与导出共用同一份解析结果，避免出现“页面按用户组过滤、导出却
按全量读取”的口径分叉。参数既支持查询串（便于脚本核对），也支持请求头
（便于前端会话透传）；同名参数只认第一个非空值。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import unquote

GROUP_KEYS = ("group", "user_group", "用户组", "当前用户组", "viewer_group")
MODE_KEYS = ("mode", "auth_mode", "grant_mode", "授权方式", "auth")
ROLE_KEYS = ("role", "audit_role", "角色")
OPERATOR_KEYS = ("operator", "操作人", "viewer")

HEADER_ALIASES = {
    "x-user-group": "group",
    "x-user-groups": "group",
    "x-current-group": "group",
    "x-auth-mode": "mode",
    "x-grant-mode": "mode",
    "x-audit-role": "role",
    "x-operator": "operator",
}

MODE_LABELS = {"group": "按当前用户组", "operator": "按操作人归属"}
GROUP_MODE_VALUES = {"group", "by_group", "current_group", "当前用户组", "按当前用户组"}
OPERATOR_MODE_VALUES = {"operator", "owner", "operator_owner", "操作人归属", "按操作人归属"}
VIEWER_ROLES = {"viewer", "readonly", "read_only", "read-only", "只读", "只读用户", "只读审计员"}

_FIRST_VALUES = {
    "group": GROUP_KEYS,
    "mode": MODE_KEYS,
    "role": ROLE_KEYS,
    "operator": OPERATOR_KEYS,
}


def normalize_mode(value: str | None) -> str:
    """把多种授权方式写法归一到 group / operator。"""
    text = (value or "").strip()
    folded = text.casefold()
    if folded in OPERATOR_MODE_VALUES:
        return "operator"
    if folded in GROUP_MODE_VALUES:
        return "group"
    return "group"


def normalize_role(value: str | None) -> str:
    """只读角色归一为 viewer，其余按审计员处理（默认审计员）。"""
    text = (value or "auditor").strip().casefold()
    return "viewer" if text in VIEWER_ROLES else "auditor"


def normalize_group(value: str | None) -> str:
    """用户组名称去空白；多值只取第一个，避免把“共享范围”误当成当前组。"""
    text = (value or "").strip()
    if not text:
        return ""
    for separator in ("、", ",", "，", ";", "；", "|"):
        text = text.replace(separator, ",")
    first = next((part.strip() for part in text.split(",") if part.strip()), "")
    return first


def _request_value(mapping: Mapping[str, str], name: str) -> str:
    for key in _FIRST_VALUES[name]:
        value = mapping.get(key)
        if value and str(value).strip():
            return str(value).strip()
    return ""


def _header_value(headers: Mapping[str, str], name: str) -> str:
    for header, target in HEADER_ALIASES.items():
        if target != name:
            continue
        value = headers.get(header)
        if value and str(value).strip():
            # HTTP 头只能放 ASCII，前端通常把中文组名百分号编码后再传。
            return unquote(str(value).strip())
    return ""


@dataclass(frozen=True)
class AuditActor:
    """一次审计读取/导出的授权上下文。"""

    group: str = ""
    mode: str = "group"
    role: str = "auditor"
    operator: str = ""

    @property
    def is_full_view(self) -> bool:
        """未指定用户组时为全量视图；只读角色只限制写入，不缩小读取范围。"""
        return not self.group

    @property
    def is_read_only(self) -> bool:
        return self.role == "viewer"

    @property
    def grant_label(self) -> str:
        return MODE_LABELS["operator" if self.mode == "operator" else "group"]


def resolve_actor(query: Mapping[str, str], headers: Mapping[str, str]) -> AuditActor:
    """查询串优先、请求头兜底；空值不覆盖已有取值。"""
    group = _request_value(query, "group") or _header_value(headers, "group")
    mode = _request_value(query, "mode") or _header_value(headers, "mode")
    role = _request_value(query, "role") or _header_value(headers, "role")
    operator = _request_value(query, "operator") or _header_value(headers, "operator")
    return AuditActor(
        group=normalize_group(group),
        mode=normalize_mode(mode),
        role=normalize_role(role),
        operator=operator.strip(),
    )
