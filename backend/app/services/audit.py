"""数据审计业务规则：状态流转、字段校验、授权过滤与差异脱敏都收在这里。

页面列表、明细与导出共用同一套授权口径：
1. 按用户组授权时，只有归属组包含当前用户组的记录可见；
2. 按操作人归属授权时，按操作人所属组判定可见性；
3. 可见记录里，命中该用户组脱敏清单的变更字段不返回原值，
   只保留“已脱敏”标记与脱敏项数，审计结果等结论字段保持原样。
"""
from __future__ import annotations

from typing import Any

from app.services.audit_access import AuditActor
from app.services.audit_redaction import as_field_list, redaction_service
from app.store import store

MODULE = "audit"
OWNERSHIP_MODULE = "audit_ownership"
LIST_FIELDS = ["记录编号", "操作类型", "操作人", "操作对象", "操作时间", "变更内容", "审计结果", "记录状态"]
REQUIRED_FIELDS = ["记录编号", "操作类型", "操作人"]
STATUS_ORDER = ["已记录", "已审计", "异常"]
ACTION_RULES = {"提交审计": "已审计", "标记异常": "异常"}
NEGATIVE_ACTIONS = []
REDACTED = "已脱敏"
DIFF_FIELD = "差异明细"


def _split_groups(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value]
    else:
        text = str(value or "")
        for separator in ("，", "、", ";", "；", "|"):
            text = text.replace(separator, ",")
        raw = text.split(",")
    return [item.strip() for item in raw if item.strip()]


class AuditService:
    # ---------- 授权判定 ----------

    def ownership(self, record: str) -> dict[str, Any] | None:
        for row in store.rows(OWNERSHIP_MODULE):
            if str(row.get("记录编号", "")).strip() == record.strip():
                return row
        return None

    def owner_group(self, entry: dict[str, Any]) -> str:
        """操作人归属组：优先取归档数据，缺失时回退到记录里显式声明的字段。"""
        record = str(entry.get("记录编号", "")).strip()
        row = self.ownership(record)
        if row is not None:
            group = str(row.get("操作人归属组", "")).strip()
            if group:
                return group
        return str(entry.get("操作人归属组", "")).strip()

    def shared_groups(self, entry: dict[str, Any]) -> list[str]:
        """共享范围：记录自身声明与归档数据取并集，兼容历史数据。"""
        record = str(entry.get("记录编号", "")).strip()
        groups = _split_groups(entry.get("归属用户组"))
        row = self.ownership(record)
        if row is not None:
            for group in _split_groups(row.get("用户组")):
                if group not in groups:
                    groups.append(group)
        return groups

    def grants(self, entry: dict[str, Any], actor: AuditActor) -> tuple[bool, str]:
        """返回 (是否可见, 本次生效的脱敏口径用户组)。"""
        if actor.is_full_view:
            return True, ""
        if not actor.group:
            return False, ""
        if actor.mode == "operator":
            owner_group = self.owner_group(entry)
            if owner_group and owner_group == actor.group:
                return True, owner_group
            if actor.operator and actor.operator == str(entry.get("操作人", "")).strip():
                return True, owner_group or actor.group
            return False, ""
        shared = self.shared_groups(entry)
        if actor.group in shared:
            return True, actor.group
        return False, ""

    # ---------- 差异脱敏 ----------

    def redaction_fields(self, entry: dict[str, Any], scope_group: str) -> list[str]:
        if not scope_group:
            return []
        record = str(entry.get("记录编号", "")).strip()
        return redaction_service.effective_fields(record, scope_group)

    def redact(self, entry: dict[str, Any], scope_group: str) -> dict[str, Any]:
        """深拷贝一条记录并按脱敏清单裁剪差异，结论字段保持不变。"""
        view = {key: value for key, value in entry.items() if key != DIFF_FIELD}
        diffs = entry.get(DIFF_FIELD)
        if not isinstance(diffs, list):
            diffs = []
        hidden = set(self.redaction_fields(entry, scope_group))
        visible: list[dict[str, Any]] = []
        for item in diffs:
            if not isinstance(item, dict):
                continue
            field = str(item.get("字段", "")).strip()
            if field and field in hidden:
                continue
            visible.append(dict(item))
        redacted_count = sum(
            1 for item in diffs if isinstance(item, dict) and str(item.get("字段", "")).strip() in hidden)
        view[DIFF_FIELD] = visible
        view["脱敏项数"] = redacted_count
        view["已脱敏"] = redacted_count > 0
        if redacted_count:
            view["脱敏说明"] = f"{redacted_count} 个变更字段因用户组授权已脱敏，审计结论保留"
        return view

    def project(self, entry: dict[str, Any], actor: AuditActor) -> dict[str, Any] | None:
        """单条投影：越权返回 None，可见则返回裁剪后的记录。"""
        allowed, scope_group = self.grants(entry, actor)
        if not allowed:
            return None
        return self.redact(entry, scope_group)

    # ---------- 查询 ----------

    def visible_rows(self, actor: AuditActor) -> list[tuple[dict[str, Any], str]]:
        rows: list[tuple[dict[str, Any], str]] = []
        for row in store.rows(MODULE):
            allowed, scope_group = self.grants(row, actor)
            if allowed:
                rows.append((row, scope_group))
        return rows

    def list_entries(
        self,
        *,
        actor: AuditActor | None = None,
        filters: dict[str, str] | None = None,
        keyword: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        actor = actor or AuditActor()
        pairs = self.visible_rows(actor)
        for field, expected in (filters or {}).items():
            pairs = [
                (row, group) for row, group in pairs
                if expected.casefold() in str(row.get(field, "")).casefold()
            ]
        if keyword:
            pairs = [
                (row, group) for row, group in pairs
                if keyword.casefold() in str(row.get("记录编号", "")).casefold()
            ]
        if status:
            pairs = [(row, group) for row, group in pairs if row.get("status") == status]
        total = len(pairs)
        start = (page - 1) * size
        page_pairs = pairs[start:start + size]
        return [self.redact(row, group) for row, group in page_pairs], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        """原始记录，仅供需要完整字段的内部流程使用。"""
        return store.find(MODULE, entry_id)

    def get_entry_view(self, entry_id: int, actor: AuditActor) -> tuple[dict[str, Any] | None, bool]:
        """返回 (投影记录, 是否存在)；投影为 None 但记录存在表示越权。"""
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, False
        return self.project(entry, actor), True

    def diff_view(self, entry_id: int, actor: AuditActor) -> tuple[dict[str, Any] | None, str, bool]:
        """审计差异接口：消费并持久化脱敏清单，返回可见差异与主版本边界。"""
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"审计记录 {entry_id} 不存在或已归档", False
        allowed, scope_group = self.grants(entry, actor)
        if not allowed:
            return None, "当前用户组无权查看该审计记录的变更字段", True
        record = str(entry.get("记录编号", "")).strip()
        boundary = None
        if scope_group:
            checklist = redaction_service.ensure_entry(record, scope_group, creator=actor.operator or "审计员")
            boundary = {
                "清单编号": checklist.get("清单编号"),
                "版本": checklist.get("版本"),
                "主版本": checklist.get("主版本"),
                "状态": checklist.get("状态"),
                "来源": checklist.get("来源"),
            }
        view = self.redact(entry, scope_group)
        view["脱敏清单"] = boundary
        view["授权方式"] = actor.grant_label
        view["生效用户组"] = scope_group or "全量审计"
        return view, "审计差异已按用户组授权脱敏", True

    # ---------- 写入 ----------

    def create_entry(
        self, values: dict[str, Any], *, actor: AuditActor | None = None,
    ) -> tuple[dict[str, Any] | None, list[str]]:
        actor = actor or AuditActor()
        if actor.is_read_only:
            return None, ["只读用户不能登记审计记录"]
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in LIST_FIELDS})
        diffs = values.get(DIFF_FIELD)
        entry[DIFF_FIELD] = [dict(item) for item in diffs if isinstance(item, dict)] if isinstance(diffs, list) else []
        groups = _split_groups(values.get("归属用户组"))
        if not groups and actor.group:
            groups = [actor.group]
        entry["归属用户组"] = groups
        if entry.get("审计结果") is None:
            entry["审计结果"] = "待审计确认"
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        rows.append(entry)
        if groups:
            self._register_ownership(entry, groups, actor)
        return entry, []

    def _register_ownership(self, entry: dict[str, Any], groups: list[str], actor: AuditActor) -> None:
        rows = store.rows(OWNERSHIP_MODULE)
        owner_group = actor.group if actor.mode == "group" and actor.group else groups[0]
        rows.append({
            "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
            "status": "有效",
            "pending": False,
            "abnormal": False,
            "记录编号": entry.get("记录编号"),
            "操作对象": entry.get("操作对象"),
            "用户组": groups,
            "操作人": entry.get("操作人"),
            "操作人归属组": owner_group,
            "共享范围": "、".join(groups),
            "创建时间": entry.get("操作时间"),
        })

    def run_action(
        self, entry_id: int, action: str, *, actor: AuditActor | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        actor = actor or AuditActor()
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"审计记录 {entry_id} 不存在或已归档"
        allowed, scope_group = self.grants(entry, actor)
        if not allowed:
            return None, "当前用户组无权对该审计记录执行动作"
        if actor.is_read_only:
            return None, "只读用户不能改动审计记录"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于数据审计可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        return self.redact(entry, scope_group), f"审计记录已{action}"
