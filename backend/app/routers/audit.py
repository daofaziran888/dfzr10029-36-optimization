"""数据审计接口：维护审计记录与审计脱敏清单。

页面、差异与导出共用同一份授权上下文（用户组/授权方式/角色）：
无权的记录直接不可见，可见记录中的脱敏字段不会出现在响应或 CSV 文件里。
"""
from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.schemas import ActionPayload, ActionResult, PageResult
from app.services.audit import AuditService
from app.services.audit_access import resolve_actor
from app.services.audit_redaction import redaction_service

router = APIRouter(prefix="/api/audit", tags=["数据审计"])

service = AuditService()

LIST_FIELDS = ["记录编号", "操作类型", "操作人", "操作对象", "操作时间", "变更内容", "审计结果", "记录状态"]
EXPORT_FIELDS = [*LIST_FIELDS, "差异明细", "脱敏项数"]
STATUSES = ["已记录", "已审计", "异常"]
REDACTION_STATUSES = ["有效", "历史", "待核对"]


def query_filters(request: Request) -> dict[str, str]:
    """只接受当前模块声明过的字段，忽略分页、授权等保留参数。"""
    return {
        key: value.strip()
        for key, value in request.query_params.items()
        if key in LIST_FIELDS and value.strip()
    }


def actor_from(request: Request):
    return resolve_actor(request.query_params, request.headers)


def csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def diff_cell(value: object) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def csv_response(items: list[dict], fields: list[str], filename: str) -> StreamingResponse:
    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["id", *fields, "status"])
    for item in items:
        row = [csv_cell(item.get("id"))]
        row.extend(csv_cell(diff_cell(item.get(field, ""))) for field in fields)
        row.append(csv_cell(item.get("status", "")))
        writer.writerow(row)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------- 审计脱敏清单：必须声明在 /{entry_id} 之前 ----------

def payload_values(payload: dict[str, object]) -> dict[str, object]:
    """兼容两种提交方式：字段平铺，或与其他模块一致的 values 包装。"""
    nested = payload.get("values")
    return nested if isinstance(nested, dict) else payload


@router.get("/redactions", response_model=dict)
def list_redactions(
    request: Request,
    record: str | None = Query(default=None, description="按记录编号检索"),
    group: str | None = Query(default=None, description="按用户组检索"),
    status: str | None = Query(default=None, description="有效、历史、待核对"),
) -> dict:
    """读取审计脱敏清单；普通用户组只能看到本组归属的清单。"""
    actor = actor_from(request)
    rows = redaction_service.list_entries(group=group, record=record, status=status)
    if actor.group:
        rows = [row for row in rows if str(row.get("用户组", "")).strip() == actor.group]
    return {"items": rows, "total": len(rows)}


@router.post("/redactions", response_model=ActionResult)
def create_redaction(request: Request, payload: dict[str, object]) -> ActionResult:
    """登记新的脱敏清单版本；只读用户与越权用户组会被拒绝。"""
    actor = actor_from(request)
    if actor.is_read_only:
        raise HTTPException(status_code=403, detail="只读用户不能改动审计脱敏清单")
    values = dict(payload_values(payload))
    target_group = str(values.get("用户组") or actor.group or "").strip()
    if actor.group and target_group and target_group != actor.group:
        raise HTTPException(status_code=403, detail="当前用户组无权改动其他用户组的审计脱敏清单")
    if target_group:
        values["用户组"] = target_group
    entry, message, conflict = redaction_service.save(values, creator=actor.operator or "审计员")
    if entry is None:
        return ActionResult(ok=False, message=message)
    return ActionResult(ok=not conflict, message=message, entry=entry)


def _redaction_visible(row: dict, actor) -> bool:
    if not actor.group:
        return True
    return str(row.get("用户组", "")).strip() == actor.group


def _redaction_by_id_or_403(entry_id: int, actor) -> dict:
    entry = redaction_service.get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"审计脱敏清单 {entry_id} 不存在或已归档")
    if not _redaction_visible(entry, actor):
        raise HTTPException(status_code=403, detail="当前用户组无权查看该审计脱敏清单")
    return entry


@router.get("/redactions/{entry_id}", response_model=dict)
def get_redaction(request: Request, entry_id: int) -> dict:
    return _redaction_by_id_or_403(entry_id, actor_from(request))


@router.get("/redactions/{entry_id}/lineage", response_model=dict)
def get_redaction_lineage(request: Request, entry_id: int) -> dict:
    """按来源追溯同一段清单的全部版本，回退后仍能串起来。"""
    actor = actor_from(request)
    entry = _redaction_by_id_or_403(entry_id, actor)
    rows = redaction_service.lineage(
        str(entry.get("记录编号", "")), str(entry.get("用户组", "")))
    return {
        "来源": entry.get("来源"),
        "记录编号": entry.get("记录编号"),
        "用户组": entry.get("用户组"),
        "items": rows,
        "total": len(rows),
    }


@router.post("/redactions/{entry_id}/actions", response_model=ActionResult)
def run_redaction_action(request: Request, entry_id: int, payload: ActionPayload) -> ActionResult:
    """回退清单版本或核对冲突版本；只读用户不能改动。"""
    actor = actor_from(request)
    if actor.is_read_only:
        raise HTTPException(status_code=403, detail="只读用户不能改动审计脱敏清单")
    entry = _redaction_by_id_or_403(entry_id, actor)
    updated, message = redaction_service.run_action(entry["id"], payload.action.strip())
    if updated is None:
        return ActionResult(ok=False, message=message)
    return ActionResult(ok=True, message=message, entry=updated)


# ---------- 审计记录 ----------

@router.get("", response_model=PageResult[dict])
def list_entries(
    request: Request,
    keyword: str | None = Query(default=None, description="按记录编号检索"),
    status: str | None = Query(default=None, description="已记录、已审计、异常"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
) -> PageResult[dict]:
    """按页面字段、记录编号关键字、状态与当前用户组授权过滤数据审计列表。"""
    items, total = service.list_entries(
        actor=actor_from(request), filters=query_filters(request), keyword=keyword,
        status=status, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/export")
def export_entries(
    request: Request,
    keyword: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> StreamingResponse:
    """下载当前筛选条件下的 UTF-8 CSV；授权过滤与差异脱敏和页面完全一致。"""
    items, _ = service.list_entries(
        actor=actor_from(request), filters=query_filters(request), keyword=keyword,
        status=status, page=1, size=1000000)
    return csv_response(items, EXPORT_FIELDS, "audit.csv")


@router.get("/{entry_id}", response_model=dict)
def get_entry(request: Request, entry_id: int) -> dict:
    """读取单条审计记录明细；越权查看直接拒绝。"""
    entry, exists = service.get_entry_view(entry_id, actor_from(request))
    if not exists:
        raise HTTPException(status_code=404, detail=f"审计记录 {entry_id} 不存在或已归档")
    if entry is None:
        raise HTTPException(status_code=403, detail="当前用户组无权查看该审计记录")
    return entry


@router.get("/{entry_id}/diff", response_model=dict)
def get_entry_diff(request: Request, entry_id: int) -> dict:
    """审计差异接口：消费并持久化脱敏清单，返回可见差异与主版本边界。"""
    view, message, exists = service.diff_view(entry_id, actor_from(request))
    if not exists:
        raise HTTPException(status_code=404, detail=message)
    if view is None:
        raise HTTPException(status_code=403, detail=message)
    return {**view, "message": message}


@router.post("", response_model=ActionResult)
def create_entry(request: Request, payload: dict[str, object]) -> ActionResult:
    """登记一条审计记录，缺字段时说明原因而不是静默丢弃。"""
    actor = actor_from(request)
    if actor.is_read_only:
        raise HTTPException(status_code=403, detail="只读用户不能登记审计记录")
    entry, missing = service.create_entry(payload_values(payload), actor=actor)
    if missing:
        return ActionResult(ok=False, message=f"缺少必填字段：{'、'.join(missing)}")
    # 返回值同样走授权投影，避免新建记录把脱敏字段从另一条路径带出来。
    view = service.project(entry, actor) if entry is not None else None
    return ActionResult(ok=True, message="审计记录已登记", entry=view)


@router.post("/{entry_id}/actions", response_model=ActionResult)
def run_action(request: Request, entry_id: int, payload: ActionPayload) -> ActionResult:
    """对单条审计记录执行提交审计、标记异常；越权与只读都会被拦下。"""
    actor = actor_from(request)
    if actor.is_read_only:
        raise HTTPException(status_code=403, detail="只读用户不能改动审计记录")
    entry, message = service.run_action(entry_id, payload.action.strip(), actor=actor)
    if entry is None:
        status_code = 404 if "不存在或已归档" in message else 403
        raise HTTPException(status_code=status_code, detail=message)
    return ActionResult(ok=True, message=message, entry=entry)
