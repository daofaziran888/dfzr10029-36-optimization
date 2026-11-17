<template>
  <section class="page" data-module="audit">
    <header class="page-head">
      <div>
        <h2>数据审计管理</h2>
        <p class="page-desc">维护审计记录，围绕记录编号、操作类型、操作人、操作对象做登记、筛选与状态流转；差异按用户组授权脱敏展示。</p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-create" type="button" :disabled="readOnly" @click="openCreate">登记审计记录</button>
        <button class="btn" data-testid="export" type="button" @click="exportRows">导出数据审计清单</button>
      </div>
    </header>

    <form class="access-bar" data-testid="audit-access" @submit.prevent="reload">
      <label class="filter-item">
        <span>当前用户组</span>
        <select v-model="accessGroup" data-testid="audit-group" @change="applyAccess">
          <option value="">全部用户组（审计员全量）</option>
          <option v-for="group in groupOptions" :key="group" :value="group">{{ group }}</option>
        </select>
      </label>
      <label class="filter-item">
        <span>授权方式</span>
        <select v-model="authMode" data-testid="audit-mode" @change="applyAccess">
          <option value="group">按当前用户组</option>
          <option value="operator">按操作人归属</option>
        </select>
      </label>
      <label class="filter-item">
        <span>角色</span>
        <select v-model="role" data-testid="audit-role" @change="applyAccess">
          <option value="auditor">审计员</option>
          <option value="viewer">只读用户</option>
        </select>
      </label>
      <button class="btn" data-testid="query" type="submit">查询</button>
      <button class="btn ghost" data-testid="reset" type="button" @click="resetFilters">重置条件</button>
      <button class="btn ghost" data-testid="open-redactions" type="button" @click="toggleRedactions">审计脱敏清单</button>
    </form>

    <form class="filter-bar" @submit.prevent="reload">
      <label v-for="field in filterFields" :key="field" class="filter-item">
        <span>{{ field }}</span>
        <input v-model="filters[field]" :data-testid="`filter-${field}`" :placeholder="`按${field}检索`" />
      </label>
    </form>

    <p v-if="accessGroup" class="access-hint" data-testid="audit-access-hint">
      当前展示 {{ accessGroup }} · {{ authMode === 'operator' ? '按操作人归属' : '按当前用户组' }} 授权结果，
      无权查看的变更字段已脱敏，审计结论保留。
    </p>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>差异可见性</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :data-testid="`row-${row.id}`" :data-status="String(row.status)">
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td data-testid="diff-summary">
            <template v-if="row['已脱敏']">{{ row['脱敏说明'] }}</template>
            <template v-else>{{ (row['差异明细'] || []).length }} 项原始差异</template>
            <button class="link" type="button" :data-testid="`diff-${row.id}`" @click="openDiff(row)">查看差异</button>
          </td>
          <td class="row-actions">
            <button
              v-for="action in actions"
              :key="action"
              class="link"
              type="button"
              :disabled="readOnly"
              :data-testid="`action-${row.id}-${action}`"
              @click="runAction(action, row)"
            >
              {{ action }}
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 2" class="empty-state">当前用户组没有可读的数据审计记录</td>
        </tr>
      </tbody>
    </table>

    <section v-if="showRedactions" class="panel" data-testid="redaction-panel">
      <header class="panel-head">
        <strong>审计脱敏清单</strong>
        <button class="btn ghost" type="button" data-testid="close-redactions" @click="showRedactions = false">关闭</button>
      </header>
      <p class="page-desc">按记录编号与用户组分片，保留历史版本；任意时刻只有一个有效主版本，回退后仍可追溯同一来源。</p>
      <table class="data-table">
        <thead>
          <tr><th>清单编号</th><th>记录编号</th><th>用户组</th><th>脱敏字段</th><th>版本</th><th>主版本</th><th>状态</th><th>来源</th><th>操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="item in redactions" :key="String(item.id)" :data-testid="`redaction-${item.id}`">
            <td>{{ item['清单编号'] }}</td>
            <td>{{ item['记录编号'] }}</td>
            <td>{{ item['用户组'] }}</td>
            <td>{{ (item['脱敏字段'] || []).join('、') || '—' }}</td>
            <td>{{ item['版本'] }}</td>
            <td>{{ item['主版本'] ? '是' : '否' }}</td>
            <td>{{ item['状态'] }}</td>
            <td>{{ item['来源'] }}</td>
            <td class="row-actions">
              <button class="link" type="button" :data-testid="`lineage-${item.id}`" @click="loadLineage(item)">追溯来源</button>
              <button
                class="link"
                type="button"
                :disabled="readOnly || item['状态'] === '待核对'"
                :data-testid="`rollback-${item.id}`"
                @click="rollbackRedaction(item)"
              >回退版本</button>
              <button
                class="link"
                type="button"
                :disabled="readOnly || item['状态'] !== '待核对'"
                :data-testid="`resolve-${item.id}`"
                @click="resolveRedaction(item)"
              >核对冲突</button>
            </td>
          </tr>
          <tr v-if="!redactions.length">
            <td colspan="9" class="empty-state">当前用户组暂无审计脱敏清单</td>
          </tr>
        </tbody>
      </table>
      <div v-if="lineage" class="lineage" data-testid="redaction-lineage">
        <strong>来源追溯：{{ lineage['记录编号'] }} → {{ lineage['来源'] }}</strong>
        <ul>
          <li v-for="item in lineage.items" :key="String(item.id)" :data-testid="`lineage-item-${item.id}`">
            第 {{ item['版本'] }} 版 · {{ item['状态'] }} · {{ item['主版本'] ? '有效主版本' : '非主版本' }}
            · 字段：{{ (item['脱敏字段'] || []).join('、') || '无' }}
          </li>
        </ul>
      </div>
    </section>

    <div v-if="showCreate" class="modal-backdrop" data-testid="create-modal">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>登记审计记录</h3>
        <label v-for="field in columns" :key="field" class="create-field">
          <span>{{ field }}</span>
          <input v-model="createValues[field]" :data-testid="`create-${field}`" required />
        </label>
        <div class="page-actions">
          <button class="btn" type="button" @click="showCreate = false">取消</button>
          <button class="btn primary" data-testid="submit-create" type="submit" :disabled="creating">
            {{ creating ? '提交中…' : '确认登记' }}
          </button>
        </div>
      </form>
    </div>

    <div v-if="diffView" class="modal-backdrop" data-testid="diff-modal">
      <div class="modal">
        <h3>{{ diffView['记录编号'] }} 差异明细</h3>
        <p class="page-desc">
          生效用户组：{{ diffView['生效用户组'] }} · 授权方式：{{ diffView['授权方式'] }}
          <template v-if="diffView['脱敏清单']">· 脱敏清单主版本：第 {{ diffView['脱敏清单']['版本'] }} 版</template>
        </p>
        <p v-if="diffView['已脱敏']" class="access-hint" data-testid="diff-redacted">{{ diffView['脱敏说明'] }}</p>
        <table class="data-table">
          <thead><tr><th>变更字段</th><th>原值</th><th>新值</th></tr></thead>
          <tbody>
            <tr v-for="(item, index) in diffView['差异明细'] || []" :key="index" data-testid="diff-item">
              <td>{{ item['字段'] }}</td>
              <td>{{ item['原值'] }}</td>
              <td>{{ item['新值'] }}</td>
            </tr>
            <tr v-if="!(diffView['差异明细'] || []).length">
              <td colspan="3" class="empty-state">没有当前用户组可读的变更字段</td>
            </tr>
          </tbody>
        </table>
        <p class="page-desc">审计结果：{{ diffView['审计结果'] }} · 状态：{{ diffView['status'] }}</p>
        <div class="page-actions">
          <button class="btn" type="button" data-testid="close-diff" @click="diffView = null">关闭</button>
        </div>
      </div>
    </div>

    <footer class="page-foot">
      <span>共 {{ total }} 条数据审计记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { request } from '@/api/client'
import { useSessionStore } from '@/stores/session'

type Row = Record<string, any>

const ENDPOINT = '/api/audit'
const columns = ["记录编号", "操作类型", "操作人", "操作对象", "操作时间", "变更内容", "审计结果", "记录状态"]
const actions = ["提交审计", "标记异常"]
const statuses = ["已记录", "已审计", "异常"]
const metricNames = ["审计记录数", "异常记录数", "已审计记录数"]
const groupOptions = ["分析用户组样例1", "分析用户组样例2", "分析用户组样例3"]

const session = useSessionStore()
const rows = ref<Row[]>([])
const total = ref(0)
const errorMessage = ref('')
const filters = ref<Record<string, string>>({})
const filterFields = columns.slice(0, 3)
const showCreate = ref(false)
const creating = ref(false)
const createValues = ref<Record<string, string>>({})
const accessGroup = ref(session.group)
const authMode = ref(session.authMode)
const role = ref(session.role)
const showRedactions = ref(false)
const redactions = ref<Row[]>([])
const lineage = ref<Row | null>(null)
const diffView = ref<Row | null>(null)

const readOnly = computed(() => role.value === 'viewer')
const stats = computed(() => [
  { label: metricNames[0], value: total.value },
  { label: metricNames[1], value: rows.value.filter((row) => row.status === statuses[1]).length },
  { label: metricNames[2], value: rows.value.filter((row) => row.status === statuses[statuses.length - 1]).length },
])

function accessQuery(): URLSearchParams {
  const query = new URLSearchParams()
  if (accessGroup.value) query.set('group', accessGroup.value)
  query.set('mode', authMode.value)
  query.set('role', role.value)
  return query
}

function withFilters(): URLSearchParams {
  const query = accessQuery()
  Object.entries(filters.value).forEach(([key, value]) => {
    if (value) query.set(key, value)
  })
  return query
}

function applyAccess() {
  session.setAuditAccess({ group: accessGroup.value, authMode: authMode.value, role: role.value })
  lineage.value = null
  diffView.value = null
  void reload()
  if (showRedactions.value) void loadRedactions()
}

function resetFilters() {
  filters.value = {}
  void reload()
}

async function exportRows() {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/export?${withFilters().toString()}`)
    if (!response.ok) throw new Error('导出失败，请稍后重试')
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url
    link.download = 'audit.csv'
    link.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '导出失败'
  }
}

function openCreate() {
  createValues.value = Object.fromEntries(columns.map((field) => [field, '']))
  errorMessage.value = ''
  showCreate.value = true
}

async function submitCreate() {
  creating.value = true
  errorMessage.value = ''
  try {
    const values: Row = { ...createValues.value }
    if (accessGroup.value) values['归属用户组'] = [accessGroup.value]
    if (accessGroup.value) values['操作人归属组'] = accessGroup.value
    const response = await request(`${ENDPOINT}?${accessQuery().toString()}`, {
      method: 'POST', body: JSON.stringify(values),
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok || !payload.ok) throw new Error(payload.message || payload.detail || '登记失败')
    showCreate.value = false
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '登记失败'
  } finally {
    creating.value = false
  }
}

async function runAction(action: string, row: Row) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/${row.id}/actions?${accessQuery().toString()}`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.message || payload.detail || '数据审计动作未生效，请稍后重试')
    }
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '数据审计操作失败'
  }
}

async function openDiff(row: Row) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/${row.id}/diff?${accessQuery().toString()}`)
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload.detail || '当前用户组无权查看该审计差异')
    diffView.value = payload
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '审计差异读取失败'
  }
}

async function toggleRedactions() {
  showRedactions.value = !showRedactions.value
  lineage.value = null
  if (showRedactions.value) await loadRedactions()
}

async function loadRedactions() {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/redactions?${accessQuery().toString()}`)
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || '审计脱敏清单读取失败')
    redactions.value = payload.items ?? []
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '审计脱敏清单读取失败'
  }
}

async function loadLineage(item: Row) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/redactions/${item.id}/lineage?${accessQuery().toString()}`)
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || '审计脱敏清单来源追溯失败')
    lineage.value = payload
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '审计脱敏清单来源追溯失败'
  }
}

async function redactionAction(item: Row, action: string) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/redactions/${item.id}/actions?${accessQuery().toString()}`, {
      method: 'POST', body: JSON.stringify({ action }),
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok || !payload.ok) throw new Error(payload.message || payload.detail || '审计脱敏清单动作未生效')
    await loadRedactions()
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '审计脱敏清单动作未生效'
  }
}

function rollbackRedaction(item: Row) {
  void redactionAction(item, '回退版本')
}

function resolveRedaction(item: Row) {
  void redactionAction(item, '核对冲突')
}

async function reload() {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}?${withFilters().toString()}`)
    if (!response.ok) {
      throw new Error('审计记录列表读取失败')
    }
    const payload = await response.json()
    rows.value = payload.items ?? []
    total.value = payload.total ?? rows.value.length
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '数据审计列表读取失败'
  }
}

onMounted(reload)
</script>

<style scoped>
.access-bar { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 10px; }
.access-bar select { border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; font-size: 13px; }
.access-hint { background: #eff6ff; border: 1px solid #bfdbfe; color: #1e3a8a; border-radius: 6px; padding: 8px 10px; font-size: 12px; margin: 0 0 10px; }
.panel { background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-top: 14px; }
.panel-head { display: flex; justify-content: space-between; align-items: center; }
.lineage { margin-top: 10px; background: #fafbfc; border-top: 1px solid var(--border); padding-top: 8px; font-size: 12px; }
.lineage ul { margin: 6px 0 0; padding-left: 18px; }
</style>
