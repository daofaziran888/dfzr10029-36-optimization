import { defineStore } from 'pinia'

export const useSessionStore = defineStore('session', {
  state: () => ({
    operator: '值班管理员',
    shiftLabel: '白班 08:00-20:00',
    scope: '数据分析实验与数据应用服务平台',
    // 审计授权上下文：组为空表示审计员全量视图，普通用户组只能看到本组可读的差异。
    group: '',
    authMode: 'group',
    role: 'auditor',
  }),
  getters: {
    canOperate: (state) => state.operator.length > 0,
    isReadOnly: (state) => state.role === 'viewer',
  },
  actions: {
    setShift(label: string) {
      this.shiftLabel = label
    },
    setAuditAccess(payload: { group?: string; authMode?: string; role?: string }) {
      if (payload.group !== undefined) this.group = payload.group
      if (payload.authMode !== undefined) this.authMode = payload.authMode
      if (payload.role !== undefined) this.role = payload.role
    },
  },
})
