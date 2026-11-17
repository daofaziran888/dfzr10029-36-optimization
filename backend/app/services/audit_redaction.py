"""审计脱敏清单：版本、主版本边界与并发写入都收在这里。

清单按「记录编号 + 用户组」分片，允许保留历史版本，但任意时刻只能有一个
有效主版本。写入按既有数据次序（id 递增）追加，版本号取当前最大版本 + 1；
并发写入由模块级锁串行化，后到的写入不会覆盖先到的主版本，只会成为新版本。
"""
from __future__ import annotations

import threading
from typing import Any

from app.store import store

MODULE = "audit_redaction"
LIST_FIELDS = ["清单编号", "记录编号", "用户组", "脱敏字段", "脱敏方式", "来源", "版本", "主版本", "状态", "授权方式", "创建人", "创建时间"]
REQUIRED_FIELDS = ["记录编号", "用户组"]
ACTION_RULES = {"回退版本": "rollback", "核对冲突": "resolve"}
STATUS_ORDER = ["有效", "历史", "待核对"]
REDACTED_PLACEHOLDER = "已脱敏"

_LOCK = threading.RLock()


def as_field_list(value: Any) -> list[str]:
    """脱敏字段既支持数组，也支持逗号/顿号分隔的文本。"""
    if isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value]
    else:
        text = str(value or "")
        for separator in ("，", "、", ";", "；", "|"):
            text = text.replace(separator, ",")
        raw = text.split(",")
    seen: list[str] = []
    for item in raw:
        name = item.strip()
        if name and name not in seen:
            seen.append(name)
    return seen


class AuditRedactionService:
    """审计脱敏清单的读取、版本写入与回退。"""

    # ---------- 读取 ----------

    def rows(self) -> list[dict[str, Any]]:
        return sorted(store.rows(MODULE), key=lambda row: int(row.get("id", 0)))

    def list_entries(
        self,
        *,
        group: str | None = None,
        record: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = self.rows()
        if group:
            rows = [row for row in rows if str(row.get("用户组", "")).strip() == group.strip()]
        if record:
            rows = [row for row in rows if str(row.get("记录编号", "")).strip() == record.strip()]
        if status:
            rows = [row for row in rows if row.get("状态") == status]
        return [dict(row) for row in rows]

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        row = store.find(MODULE, entry_id)
        return dict(row) if row else None

    def lineage(self, record: str, group: str) -> list[dict[str, Any]]:
        """按来源追溯同一段清单的所有版本，回退后仍能看到完整来源。"""
        return [
            dict(row) for row in self.rows()
            if str(row.get("记录编号", "")).strip() == record.strip()
            and str(row.get("用户组", "")).strip() == group.strip()
        ]

    def main_version(self, record: str, group: str) -> dict[str, Any] | None:
        for row in self.rows():
            if (str(row.get("记录编号", "")).strip() == record.strip()
                    and str(row.get("用户组", "")).strip() == group.strip()
                    and row.get("主版本") is True
                    and row.get("状态") == "有效"):
                return dict(row)
        return None

    def effective_fields(self, record: str, group: str) -> list[str]:
        """供审计差异接口与导出共用：只认当前有效主版本。"""
        if not record or not group:
            return []
        entry = self.main_version(record, group)
        return as_field_list(entry.get("脱敏字段")) if entry else []

    def ensure_entry(self, record: str, group: str, creator: str = "审计员") -> dict[str, Any]:
        """审计差异接口消费清单时补一份持久化底稿，保持可追溯且不改变结论。"""
        with _LOCK:
            existing = self.main_version(record, group)
            if existing is not None:
                return existing
            history = self.lineage(record, group)
            version = max((int(row.get("版本", 0)) for row in history), default=0) + 1
            entry = {
                "id": self._next_id(),
                "status": "有效",
                "pending": False,
                "abnormal": False,
                "清单编号": self._next_code(),
                "记录编号": record.strip(),
                "用户组": group.strip(),
                "脱敏字段": [],
                "脱敏方式": "字段隐藏",
                "来源": record.strip(),
                "版本": version,
                "主版本": True,
                "状态": "有效",
                "授权方式": "按当前用户组",
                "创建人": creator,
                "创建时间": self._today(),
            }
            store.rows(MODULE).append(entry)
            return dict(entry)

    # ---------- 写入 ----------

    def save(self, values: dict[str, Any], *, creator: str = "审计员") -> tuple[dict[str, Any] | None, str, bool]:
        """新增清单版本；返回 (记录, 说明, 是否冲突待核对)。"""
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, f"缺少必填字段：{'、'.join(missing)}", False
        record = str(values.get("记录编号", "")).strip()
        group = str(values.get("用户组", "")).strip()
        requested_version = values.get("版本")
        with _LOCK:
            history = self.lineage(record, group)
            next_version = max((int(row.get("版本", 0)) for row in history), default=0) + 1
            conflict = (
                requested_version is not None
                and str(requested_version).strip() != ""
                and int(requested_version) != next_version
            )
            entry = {
                "id": self._next_id(),
                "status": "待核对" if conflict else "有效",
                "pending": conflict,
                "abnormal": False,
                "清单编号": self._next_code(),
                "记录编号": record,
                "用户组": group,
                "脱敏字段": as_field_list(values.get("脱敏字段")),
                "脱敏方式": str(values.get("脱敏方式") or "字段隐藏").strip(),
                "来源": str(values.get("来源") or record).strip(),
                "版本": int(requested_version) if conflict else next_version,
                "主版本": False if conflict else True,
                "状态": "待核对" if conflict else "有效",
                "授权方式": str(values.get("授权方式") or "按当前用户组").strip(),
                "创建人": str(values.get("创建人") or creator).strip(),
                "创建时间": self._today(),
            }
            if not conflict:
                self._promote(entry, history)
            store.rows(MODULE).append(entry)
            if conflict:
                return dict(entry), (
                    f"清单版本 {entry['版本']} 与现有主版本边界不一致，已登记为待核对，"
                    f"当前有效版本仍为 {next_version - 1}"
                ), True
            return dict(entry), f"审计脱敏清单已登记为第 {entry['版本']} 版（有效主版本）", False

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        """回退到某个历史版本，或对冲突版本做核对。"""
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"审计脱敏清单 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于审计脱敏清单可执行范围"
        record = str(entry.get("记录编号", "")).strip()
        group = str(entry.get("用户组", "")).strip()
        with _LOCK:
            history = self.lineage(record, group)
            if ACTION_RULES[action] == "rollback":
                if entry.get("状态") == "待核对":
                    return None, "冲突版本尚未核对，不能直接回退"
                self._promote(entry, history)
                entry["状态"] = "有效"
                entry["pending"] = False
                return dict(entry), (
                    f"已回退到第 {entry.get('版本')} 版，来源仍追溯至 {entry.get('来源')}"
                )
            if entry.get("状态") != "待核对":
                return None, f"审计脱敏清单 {entry_id} 当前不是冲突版本，无需核对"
            # 核对冲突时按已确认版本重新编号，避免把冲突请求里的越界版本号带进主线。
            settled = [row for row in history if row.get("状态") in ("有效", "历史")]
            next_version = max((int(row.get("版本", 0)) for row in settled), default=0) + 1
            entry["版本"] = next_version
            entry["状态"] = "有效"
            entry["pending"] = False
            self._promote(entry, history)
            return dict(entry), f"冲突已核对，第 {next_version} 版成为有效主版本"

    # ---------- 内部 ----------

    def _promote(self, entry: dict[str, Any], history: list[dict[str, Any]]) -> None:
        """同一分片只保留一个有效主版本，其余降为历史，保证并发后只落一版。

        history 只是分片快照（可能是拷贝），降级必须落在仓库里的真实行上，
        否则旧主版本会继续以「有效主版本」身份参与授权过滤。
        """
        record = str(entry.get("记录编号", "")).strip()
        group = str(entry.get("用户组", "")).strip()
        for row in store.rows(MODULE):
            if (str(row.get("记录编号", "")).strip() != record
                    or str(row.get("用户组", "")).strip() != group
                    or row.get("id") == entry.get("id")
                    or row.get("状态") == "待核对"):
                continue
            row["主版本"] = False
            if row.get("状态") == "有效":
                row["状态"] = "历史"
            row["pending"] = False
        for row in history:
            if row.get("id") == entry.get("id"):
                continue
            row["主版本"] = False
            if row.get("状态") == "有效":
                row["状态"] = "历史"
            row["pending"] = False
        entry["主版本"] = True
        entry["状态"] = "有效"
        entry["pending"] = False

    def _next_id(self) -> int:
        return max((int(row.get("id", 0)) for row in store.rows(MODULE)), default=0) + 1

    def _next_code(self) -> str:
        return f"REDA-{self._next_id():04d}"

    @staticmethod
    def _today() -> str:
        from datetime import date

        return date.today().isoformat()


redaction_service = AuditRedactionService()
