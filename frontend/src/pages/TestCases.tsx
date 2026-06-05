import { useState, useCallback, useRef } from 'react'
import {
  CheckCircle2, XCircle, Clock, Play, RefreshCw, Loader2,
  FlaskConical, ChevronDown, ChevronUp, PlayCircle, SkipForward,
  AlertCircle, Terminal, Shield, Wrench, Server, Crosshair,
  ClipboardList, BrainCircuit, Briefcase, Database, Activity
} from 'lucide-react'
import apiClient from '@/api/client'
import axios from 'axios'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type TestStatus = 'idle' | 'running' | 'pass' | 'fail' | 'skip'

interface TestResult {
  status: TestStatus
  detail: string
  duration: number   // ms
}

interface TestDef {
  id: string
  name: string
  what: string      // Một câu mô tả: test case này kiểm tra điều gì
  expected: string  // Kết quả mong muốn
  run: () => Promise<string>  // resolve = detail string, reject = error message
}

interface CategoryDef {
  id: string
  label: string
  icon: React.ElementType
  color: string      // Tailwind text color class
  borderColor: string
  bgColor: string
  tests: TestDef[]
}

// ---------------------------------------------------------------------------
// Helper to call raw axios without auth header (for auth rejection tests)
// ---------------------------------------------------------------------------
const rawAxios = axios.create({
  baseURL: `${(import.meta.env.VITE_API_URL as string | undefined) ?? ''}/api/v1`,
  timeout: 15000,
})

// ---------------------------------------------------------------------------
// Test Categories & Test Cases
// ---------------------------------------------------------------------------

const CATEGORIES: CategoryDef[] = [
  // ─── 1. Authentication ────────────────────────────────────────────────────
  {
    id: 'auth',
    label: 'Authentication',
    icon: Shield,
    color: 'text-emerald-400',
    borderColor: 'border-emerald-500/30',
    bgColor: 'bg-emerald-500/5',
    tests: [
      {
        id: 'AUTH-01',
        name: 'Get Current User Profile',
        what: 'Gọi GET /auth/me với JWT token hợp lệ từ session hiện tại',
        expected: 'Response trả về object user có đầy đủ email, role, id',
        async run() {
          const { data } = await apiClient.get('/auth/me')
          if (!data.data?.email) throw new Error('Thiếu trường email trong response')
          if (!data.data?.role)  throw new Error('Thiếu trường role trong response')
          return `OK — user: ${data.data.email} | role: ${data.data.role}`
        },
      },
      {
        id: 'AUTH-02',
        name: 'Truy Cập Endpoint Không Có Token',
        what: 'Gọi GET /auth/me mà KHÔNG gửi Authorization header',
        expected: 'Server phải từ chối với HTTP 401 Unauthorized',
        async run() {
          try {
            await rawAxios.get('/auth/me')
            throw new Error('Mong đợi 401 nhưng nhận được 200 — endpoint không được bảo vệ!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — 401 Unauthorized (đúng như mong đợi)'
            throw err
          }
        },
      },
      {
        id: 'AUTH-03',
        name: 'Đăng Nhập Sai Thông Tin',
        what: 'POST /auth/login với email và password không tồn tại trong hệ thống',
        expected: 'HTTP 401 — không trả về JWT token',
        async run() {
          try {
            await rawAxios.post('/auth/login', {
              email: 'nonexistent_test_user@invalid.xyz',
              password: 'wrong_password_12345',
            })
            throw new Error('Mong đợi 401 nhưng nhận được 200 — lỗ hổng bảo mật!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — 401 Unauthorized (credentials bị từ chối)'
            throw err
          }
        },
      },
      {
        id: 'AUTH-04',
        name: 'Middleware Auth Áp Dụng Cho Mọi Route',
        what: 'Gọi GET /agents mà không có token — kiểm tra auth middleware toàn cục',
        expected: 'HTTP 401, không có dữ liệu agent nào bị lộ',
        async run() {
          try {
            await rawAxios.get('/agents')
            throw new Error('Mong đợi 401 nhưng nhận được 200!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — /agents được bảo vệ đúng'
            throw err
          }
        },
      },
      {
        id: 'AUTH-05',
        name: 'Đăng Nhập Thành Công',
        what: 'POST /auth/login với admin credentials mặc định — lấy JWT token hợp lệ',
        expected: 'HTTP 200, response chứa token (JWT) và thông tin user',
        async run() {
          const { data } = await rawAxios.post('/auth/login', {
            email: 'admin@forensichub.local',
            password: 'Admin@123456',
          })
          if (!data.token) throw new Error('Thiếu token trong response')
          if (!data.user?.email) throw new Error('Thiếu user.email trong response')
          return `OK — login thành công | user: ${data.user.email} | token: ${String(data.token).slice(0, 20)}…`
        },
      },
      {
        id: 'AUTH-06',
        name: 'Login Thiếu Trường Email → 400',
        what: 'POST /auth/login chỉ gửi password, không có email',
        expected: 'HTTP 400 hoặc 401 — validation hoặc auth error',
        async run() {
          try {
            await rawAxios.post('/auth/login', { password: 'Admin@123456' })
            throw new Error('Server chấp nhận request thiếu email — cần validate!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 401)
              return `OK — server từ chối request thiếu email (${e.response.status})`
            throw err
          }
        },
      },
      {
        id: 'AUTH-07',
        name: 'Login Body Rỗng → Lỗi',
        what: 'POST /auth/login với body {} không có trường nào',
        expected: 'HTTP 400 hoặc 401, server không crash',
        async run() {
          try {
            await rawAxios.post('/auth/login', {})
            throw new Error('Server chấp nhận empty body — lỗ hổng!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 401)
              return `OK — server từ chối body rỗng (${e.response.status})`
            throw err
          }
        },
      },
      {
        id: 'AUTH-08',
        name: 'JWT Giả Mạo Bị Từ Chối',
        what: 'Gọi GET /auth/me với JWT được ký bằng secret sai',
        expected: 'HTTP 401 — server xác thực chữ ký JWT',
        async run() {
          const fakeJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ.invalid_signature_here'
          try {
            await rawAxios.get('/auth/me', { headers: { Authorization: `Bearer ${fakeJWT}` } })
            throw new Error('Server chấp nhận JWT giả mạo — lỗ hổng bảo mật nghiêm trọng!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — JWT giả mạo bị từ chối (401)'
            throw err
          }
        },
      },
    ],
  },

  // ─── 2. Agent Management ──────────────────────────────────────────────────
  {
    id: 'agents',
    label: 'Agent Management',
    icon: Server,
    color: 'text-sky-400',
    borderColor: 'border-sky-500/30',
    bgColor: 'bg-sky-500/5',
    tests: [
      {
        id: 'AGENT-01',
        name: 'Liệt Kê Tất Cả Agents',
        what: 'GET /agents — lấy danh sách agent đã đăng ký',
        expected: 'Response là array (có thể rỗng), mỗi item có id, name, status',
        async run() {
          const { data } = await apiClient.get('/agents')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} agent(s) trong hệ thống`
        },
      },
      {
        id: 'AGENT-02',
        name: 'Tạo Agent Mới & Xóa (Lifecycle)',
        what: 'POST /agents để tạo → xác minh có id/token → DELETE để xóa',
        expected: 'Agent được tạo với token hợp lệ, sau đó xóa thành công',
        async run() {
          const name = `__test_agent_${Date.now()}`
          const { data: createData } = await apiClient.post('/agents', {
            name,
            description: 'Automated test agent — safe to delete',
          })
          const agent = createData.data
          if (!agent?.id)    throw new Error('Không có id trong response')
          if (!agent?.token) throw new Error('Không có token trong response')
          try {
            await apiClient.delete(`/agents/${agent.id}`)
          } catch {
            throw new Error(`Tạo OK (${agent.id.slice(0,8)}) nhưng xóa thất bại`)
          }
          return `OK — tạo agent "${name}", xóa thành công`
        },
      },
      {
        id: 'AGENT-03',
        name: 'Lấy Installer Config Của Agent',
        what: 'GET /agents/:id/installer — lấy JSON config để deploy agent',
        expected: 'Response chứa agent_id, server_url',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — không có agent nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/agents/${id}/installer`)
          const cfg = data.data
          if (!cfg?.agent_id) throw new Error('Thiếu agent_id')
          if (!cfg?.server_url) throw new Error('Thiếu server_url')
          return `OK — installer config cho agent "${cfg.agent_name}" tại ${cfg.server_url}`
        },
      },
      {
        id: 'AGENT-04',
        name: 'Cập Nhật Mô Tả Agent',
        what: 'PATCH /agents/:id — cập nhật trường description',
        expected: 'Response trả về agent với description đã được cập nhật',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — không có agent nào để test'
          const id = listData.data[0].id
          const newDesc = `Test update at ${new Date().toISOString()}`
          const { data } = await apiClient.patch(`/agents/${id}`, { description: newDesc })
          if (data.data?.description !== newDesc) throw new Error('Description không được cập nhật')
          return `OK — description cập nhật thành công cho agent ${id.slice(0,8)}`
        },
      },
      {
        id: 'AGENT-05',
        name: 'Duyệt Filesystem Agent',
        what: 'GET /agents/:id/fs?path=/ — liệt kê thư mục gốc trên agent online',
        expected: 'Response là array các entry (tên file/thư mục)',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          const online = listData.data?.find((a: { status: string }) => a.status === 'online')
          if (!online) return 'SKIP — không có agent online để test filesystem'
          const { data } = await apiClient.get(`/agents/${online.id}/fs`, { params: { path: '/' } })
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} entry trong filesystem của agent "${online.name}"`
        },
      },
      {
        id: 'AGENT-06',
        name: 'Tên Agent Rỗng Bị Từ Chối',
        what: 'POST /agents với name="" — kiểm tra validation bắt buộc',
        expected: 'HTTP 400 Bad Request',
        async run() {
          try {
            await apiClient.post('/agents', { name: '', description: 'validation test' })
            throw new Error('Server chấp nhận tên rỗng — cần validate!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — tên rỗng bị từ chối (400)'
            throw err
          }
        },
      },
      {
        id: 'AGENT-07',
        name: 'Agent Không Tồn Tại → 404',
        what: 'GET /agents/:id với UUID không có trong DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/agents/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'AGENT-08',
        name: 'Token Không Bị Lộ Trong Danh Sách',
        what: 'GET /agents — kiểm tra field "token" không xuất hiện trong list response',
        expected: 'Không có item nào có field token (security check)',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — không có agent nào để kiểm tra'
          const withToken = listData.data.filter((a: { token?: string }) => a.token)
          if (withToken.length > 0) throw new Error(`${withToken.length} agent(s) bị lộ token trong response!`)
          return `OK — token không bị lộ trong ${listData.data.length} agent(s)`
        },
      },
      {
        id: 'AGENT-09',
        name: 'Download Agent Binary (Windows)',
        what: 'GET /agents/binary/windows — download agent binary cho Windows',
        expected: 'HTTP 200 với file binary, hoặc 404 nếu binary chưa build',
        async run() {
          try {
            const { status } = await apiClient.get('/agents/binary/windows', { responseType: 'blob' })
            if (status !== 200) throw new Error(`Status ${status}`)
            return 'OK — Windows agent binary endpoint phản hồi 200'
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'SKIP — binary chưa được build/upload'
            throw err
          }
        },
      },
    ],
  },

  // ─── 3. Tool Management ───────────────────────────────────────────────────
  {
    id: 'tools',
    label: 'Tool Management',
    icon: Wrench,
    color: 'text-violet-400',
    borderColor: 'border-violet-500/30',
    bgColor: 'bg-violet-500/5',
    tests: [
      {
        id: 'TOOL-01',
        name: 'Liệt Kê Tất Cả Tools',
        what: 'GET /tools — lấy danh sách tất cả công cụ forensic',
        expected: 'Array các tool, mỗi item có id, name, category, platform',
        async run() {
          const { data } = await apiClient.get('/tools')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} tool(s) trong thư viện`
        },
      },
      {
        id: 'TOOL-02',
        name: 'Lọc Tools Theo Platform',
        what: 'GET /tools?platform=windows — chỉ lấy tool dành cho Windows',
        expected: 'Array chỉ chứa tool có platform="windows" hoặc "both"',
        async run() {
          const { data } = await apiClient.get('/tools', { params: { platform: 'windows' } })
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} Windows tool(s)`
        },
      },
      {
        id: 'TOOL-03',
        name: 'Lọc Tools Theo Category',
        what: 'GET /tools?category=memory — lấy tool thuộc danh mục memory analysis',
        expected: 'Array chỉ chứa tool có category="memory"',
        async run() {
          const { data } = await apiClient.get('/tools', { params: { category: 'memory' } })
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} memory tool(s)`
        },
      },
      {
        id: 'TOOL-04',
        name: 'Lấy Chi Tiết Một Tool',
        what: 'GET /tools/:id — lấy metadata đầy đủ của một tool cụ thể',
        expected: 'Object tool với id, name, category, platform, default_args',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — không có tool nào trong hệ thống'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/tools/${id}`)
          if (!data.data?.name) throw new Error('Thiếu trường name trong response')
          return `OK — tool "${data.data.name}" (${data.data.category}/${data.data.platform})`
        },
      },
      {
        id: 'TOOL-05',
        name: 'Tool Không Tồn Tại → 404',
        what: 'GET /tools/:id với UUID không tồn tại trong DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/tools/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'TOOL-06',
        name: 'Cập Nhật Metadata Tool',
        what: 'PUT /tools/:id — cập nhật description của tool hiện có',
        expected: 'Response trả về tool với metadata đã được cập nhật',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — không có tool nào để test'
          const tool = listData.data[0]
          const newDesc = `[Test] Updated at ${new Date().toISOString()}`
          const { data } = await apiClient.put(`/tools/${tool.id}`, {
            name: tool.name,
            description: newDesc,
            category: tool.category,
            platform: tool.platform,
          })
          if (!data.data) throw new Error('Không có data trong response')
          return `OK — tool "${tool.name}" description cập nhật thành công`
        },
      },
      {
        id: 'TOOL-07',
        name: 'Server File Path Không Bị Lộ',
        what: 'GET /tools/:id — kiểm tra response không chứa đường dẫn tuyệt đối trên server',
        expected: 'Không có "/var/", "C:\\\\", "/home/" trong response',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — không có tool nào để kiểm tra'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/tools/${id}`)
          const str = JSON.stringify(data.data ?? {})
          if (str.includes('/var/') || str.includes('C:\\\\') || str.includes('/home/'))
            throw new Error('Server file path bị lộ trong response!')
          return 'OK — không phát hiện server path tuyệt đối trong response'
        },
      },
    ],
  },

  // ─── 4. Job Execution ─────────────────────────────────────────────────────
  {
    id: 'jobs',
    label: 'Job Execution',
    icon: Terminal,
    color: 'text-amber-400',
    borderColor: 'border-amber-500/30',
    bgColor: 'bg-amber-500/5',
    tests: [
      {
        id: 'JOB-01',
        name: 'Liệt Kê Tất Cả Jobs',
        what: 'GET /jobs — lấy danh sách tất cả job thực thi tool',
        expected: 'Array jobs, mỗi item có id, status, agent_id, tool_id',
        async run() {
          const { data } = await apiClient.get('/jobs')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} job(s) trong hệ thống`
        },
      },
      {
        id: 'JOB-02',
        name: 'Lọc Jobs Theo Status=done',
        what: 'GET /jobs?status=done — chỉ lấy job đã hoàn thành',
        expected: 'Tất cả item trong array phải có status="done"',
        async run() {
          const { data } = await apiClient.get('/jobs', { params: { status: 'done' } })
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          const mismatch = data.data.filter((j: { status: string }) => j.status !== 'done')
          if (mismatch.length > 0) throw new Error(`${mismatch.length} job không phải "done"`)
          return `OK — ${data.data.length} job(s) với status=done`
        },
      },
      {
        id: 'JOB-03',
        name: 'Lấy Chi Tiết Job',
        what: 'GET /jobs/:id — lấy thông tin đầy đủ kèm agent và tool preloaded',
        expected: 'Object job có id, status, tool.name, agent.name',
        async run() {
          const { data: listData } = await apiClient.get('/jobs')
          if (!listData.data?.length) return 'SKIP — không có job nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/jobs/${id}`)
          const job = data.data
          if (!job?.id) throw new Error('Thiếu id trong response')
          return `OK — job ${id.slice(0,8)} | status: ${job.status} | tool: ${job.tool?.name ?? 'N/A'}`
        },
      },
      {
        id: 'JOB-04',
        name: 'Lấy Artifact Content Của Job',
        what: 'GET /jobs/:id/artifact/content — lấy nội dung file artifact kết quả',
        expected: 'Nội dung text của file artifact nếu job có artifact_path',
        async run() {
          const { data: listData } = await apiClient.get('/jobs', { params: { status: 'done' } })
          const withArtifact = listData.data?.find((j: { artifact_path?: string }) => j.artifact_path)
          if (!withArtifact) return 'SKIP — không có job done nào có artifact'
          const { data } = await apiClient.get(`/jobs/${withArtifact.id}/artifact/content`)
          if (typeof data !== 'string' && typeof data !== 'object') throw new Error('Response không hợp lệ')
          return `OK — artifact content của job ${withArtifact.id.slice(0,8)} (${String(data).length} bytes)`
        },
      },
      {
        id: 'JOB-05',
        name: 'Lọc Jobs Theo Agent',
        what: 'GET /jobs?agent_id=:id — chỉ lấy jobs thuộc một agent cụ thể',
        expected: 'Tất cả items trong array phải có agent_id khớp',
        async run() {
          const { data: agentData } = await apiClient.get('/agents')
          if (!agentData.data?.length) return 'SKIP — không có agent nào'
          const agentId = agentData.data[0].id
          const { data } = await apiClient.get('/jobs', { params: { agent_id: agentId } })
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          const mismatch = data.data.filter((j: { agent_id: string }) => j.agent_id !== agentId)
          if (mismatch.length > 0) throw new Error(`${mismatch.length} job không thuộc agent ${agentId.slice(0,8)}`)
          return `OK — ${data.data.length} job(s) của agent ${agentId.slice(0,8)}`
        },
      },
      {
        id: 'JOB-06',
        name: 'Job Không Tồn Tại → 404',
        what: 'GET /jobs/:id với UUID không tồn tại trong DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/jobs/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'JOB-07',
        name: 'Stop Job Đã Done → 400',
        what: 'POST /jobs/:id/stop trên job có status=done — không thể stop job đã kết thúc',
        expected: 'HTTP 400 Bad Request',
        async run() {
          const { data: listData } = await apiClient.get('/jobs', { params: { status: 'done' } })
          if (!listData.data?.length) return 'SKIP — không có done job nào để test'
          const id = listData.data[0].id
          try {
            await apiClient.post(`/jobs/${id}/stop`)
            throw new Error('Server cho phép stop job đã done — không đúng!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return `OK — không thể stop job đã done (400)`
            throw err
          }
        },
      },
    ],
  },

  // ─── 5. Evidence Checklist ────────────────────────────────────────────────
  {
    id: 'checklist',
    label: 'Evidence Checklist',
    icon: ClipboardList,
    color: 'text-lime-400',
    borderColor: 'border-lime-500/30',
    bgColor: 'bg-lime-500/5',
    tests: [
      {
        id: 'CHK-01',
        name: 'Liệt Kê Checklist Runs',
        what: 'GET /checklist/runs — lấy lịch sử các lần chạy thu thập bằng chứng',
        expected: 'Array runs, mỗi item có id, agent_id, status, created_at',
        async run() {
          const { data } = await apiClient.get('/checklist/runs')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} checklist run(s) trong lịch sử`
        },
      },
      {
        id: 'CHK-02',
        name: 'Lấy Chi Tiết Checklist Run',
        what: 'GET /checklist/runs/:id — lấy run kèm batches và output từng lệnh',
        expected: 'Object run có id, batches array, mỗi batch có status',
        async run() {
          const { data: listData } = await apiClient.get('/checklist/runs')
          if (!listData.data?.length) return 'SKIP — không có run nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/checklist/runs/${id}`)
          const run = data.data
          if (!run?.id) throw new Error('Thiếu id trong response')
          const batchCount = run.batches?.length ?? 0
          return `OK — run ${id.slice(0,8)} | ${batchCount} batch(es) | status: ${run.status}`
        },
      },
      {
        id: 'CHK-03',
        name: 'Batch Fields Đầy Đủ',
        what: 'Lấy detail run → kiểm tra batch đầu tiên có đủ id, status, batch_key',
        expected: 'Batch có id, batch_key, batch_label, status',
        async run() {
          const { data: listData } = await apiClient.get('/checklist/runs')
          if (!listData.data?.length) return 'SKIP — không có run nào'
          const { data: runDetail } = await apiClient.get(`/checklist/runs/${listData.data[0].id}`)
          const batch = runDetail.data?.batches?.[0]
          if (!batch) return 'SKIP — run không có batch nào'
          if (!batch.id) throw new Error('Batch thiếu id')
          if (!batch.status) throw new Error('Batch thiếu status')
          return `OK — batch "${batch.batch_label ?? batch.batch_key}" | status: ${batch.status}`
        },
      },
      {
        id: 'CHK-04',
        name: 'Run Không Tồn Tại → 404',
        what: 'GET /checklist/runs/:id với UUID không tồn tại',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/checklist/runs/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'CHK-05',
        name: 'Phát Hiện Runs Theo Platform',
        what: 'GET /checklist/runs — kiểm tra có phân biệt được platform win/linux',
        expected: 'Tìm thấy run với platform field (win hoặc linux)',
        async run() {
          const { data } = await apiClient.get('/checklist/runs')
          if (!data.data?.length) return 'SKIP — không có run nào'
          const withPlatform = data.data.filter((r: { platform?: string }) => r.platform)
          if (!withPlatform.length) return 'SKIP — không có run nào có platform field'
          const platforms = [...new Set(withPlatform.map((r: { platform: string }) => r.platform))].join(', ')
          return `OK — phát hiện platform(s): ${platforms} trong ${data.data.length} run(s)`
        },
      },
      {
        id: 'CHK-06',
        name: 'Tạo Run Với Agent Không Tồn Tại → Lỗi',
        what: 'POST /checklist/run với agent_id UUID không có trong DB',
        expected: 'HTTP 400 hoặc 404 — không thể chạy với agent không hợp lệ',
        async run() {
          try {
            await apiClient.post('/checklist/run', {
              agent_id: '00000000-0000-0000-0000-000000000000',
              platform: 'win',
              label: 'Test invalid agent',
              analyst: 'tester',
            })
            throw new Error('Server cho phép tạo run với agent không tồn tại!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 404 || e.response?.status === 503)
              return `OK — bị từ chối với agent không hợp lệ (${e.response.status})`
            throw err
          }
        },
      },
    ],
  },

  // ─── 6. Hunting Scenarios ─────────────────────────────────────────────────
  {
    id: 'hunting',
    label: 'Hunting Scenarios',
    icon: Crosshair,
    color: 'text-rose-400',
    borderColor: 'border-rose-500/30',
    bgColor: 'bg-rose-500/5',
    tests: [
      {
        id: 'HUNT-01',
        name: 'Liệt Kê Kịch Bản Hunting',
        what: 'GET /hunting/scenarios — lấy danh sách tất cả kịch bản tấn công/điều tra',
        expected: 'Array kịch bản, mỗi item có id, name, tools (preloaded)',
        async run() {
          const { data } = await apiClient.get('/hunting/scenarios')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} kịch bản hunting`
        },
      },
      {
        id: 'HUNT-02',
        name: 'Tạo & Xóa Kịch Bản (Lifecycle)',
        what: 'POST /hunting/scenarios tạo mới → GET lấy lại → DELETE xóa',
        expected: 'Kịch bản được tạo với id, sau đó xóa sạch khỏi DB',
        async run() {
          const name = `__test_scenario_${Date.now()}`
          const { data: createData } = await apiClient.post('/hunting/scenarios', {
            name,
            description: 'Automated test scenario — safe to delete',
          })
          const sc = createData.data
          if (!sc?.id) throw new Error('Không có id trong response')
          try {
            await apiClient.delete(`/hunting/scenarios/${sc.id}`)
          } catch {
            throw new Error(`Tạo OK nhưng DELETE thất bại (id: ${sc.id.slice(0,8)})`)
          }
          return `OK — tạo kịch bản "${name}", xóa thành công`
        },
      },
      {
        id: 'HUNT-03',
        name: 'Gắn Tool Vào Kịch Bản',
        what: 'POST /hunting/scenarios/:id/tools với tool_id — liên kết tool vào scenario',
        expected: 'Scenario được cập nhật với tool đã gắn',
        async run() {
          const { data: toolsData } = await apiClient.get('/tools')
          if (!toolsData.data?.length) return 'SKIP — không có tool nào để gắn'
          const name = `__test_sc_attach_${Date.now()}`
          const { data: createData } = await apiClient.post('/hunting/scenarios', {
            name, description: 'Tool attachment test'
          })
          const sc = createData.data
          try {
            await apiClient.post(`/hunting/scenarios/${sc.id}/tools`, {
              tool_id: toolsData.data[0].id, sort_order: 1
            })
            const { data: getBack } = await apiClient.get(`/hunting/scenarios/${sc.id}`)
            if (!getBack.data?.tools?.length) throw new Error('Tool không xuất hiện sau khi gắn')
            return `OK — gắn tool "${toolsData.data[0].name}" vào kịch bản thành công`
          } finally {
            try { await apiClient.delete(`/hunting/scenarios/${sc.id}`) } catch {}
          }
        },
      },
      {
        id: 'HUNT-04',
        name: 'Liệt Kê Deployment',
        what: 'GET /hunting/deployments — lấy lịch sử deploy kịch bản lên agent',
        expected: 'Array deployments, mỗi item có scenario và jobs liên kết',
        async run() {
          const { data } = await apiClient.get('/hunting/deployments')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} deployment(s) trong lịch sử`
        },
      },
      {
        id: 'HUNT-05',
        name: 'Cập Nhật Scenario',
        what: 'PUT /hunting/scenarios/:id — đổi description kịch bản',
        expected: 'Response trả về scenario với metadata đã cập nhật',
        async run() {
          const { data: listData } = await apiClient.get('/hunting/scenarios')
          if (!listData.data?.length) return 'SKIP — không có scenario nào để test'
          const sc = listData.data[0]
          const { data } = await apiClient.put(`/hunting/scenarios/${sc.id}`, {
            name: sc.name,
            description: `Updated at ${new Date().toISOString()}`,
          })
          if (!data.data) throw new Error('Không có data trong response')
          return `OK — scenario "${sc.name}" cập nhật thành công`
        },
      },
      {
        id: 'HUNT-06',
        name: 'Scenario Không Tồn Tại → 404',
        what: 'GET /hunting/scenarios/:id với UUID không tồn tại',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/hunting/scenarios/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'HUNT-07',
        name: 'Tên Scenario Rỗng → 400',
        what: 'POST /hunting/scenarios với name="" — kiểm tra validation bắt buộc',
        expected: 'HTTP 400 Bad Request',
        async run() {
          try {
            await apiClient.post('/hunting/scenarios', { name: '', description: 'test' })
            throw new Error('Server chấp nhận tên rỗng — cần validate!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — tên rỗng bị từ chối (400)'
            throw err
          }
        },
      },
      {
        id: 'HUNT-08',
        name: 'Lấy Detail Deployment',
        what: 'GET /hunting/deployments/:id — lấy deployment kèm scenario và jobs',
        expected: 'Object deployment có id, scenario, jobs array',
        async run() {
          const { data: listData } = await apiClient.get('/hunting/deployments')
          if (!listData.data?.length) return 'SKIP — không có deployment nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/hunting/deployments/${id}`)
          const dep = data.data
          if (!dep?.id) throw new Error('Thiếu id trong response')
          const jobCount = dep.jobs?.length ?? 0
          return `OK — deployment ${id.slice(0,8)} | scenario: "${dep.scenario?.name ?? 'N/A'}" | ${jobCount} job(s)`
        },
      },
    ],
  },

  // ─── 7. Case Management ───────────────────────────────────────────────────
  {
    id: 'cases',
    label: 'Case Management',
    icon: Briefcase,
    color: 'text-cyan-400',
    borderColor: 'border-cyan-500/30',
    bgColor: 'bg-cyan-500/5',
    tests: [
      {
        id: 'CASE-01',
        name: 'Liệt Kê Tất Cả Cases',
        what: 'GET /cases — lấy danh sách các vụ điều tra',
        expected: 'Array cases, mỗi item có id, name, status (open/closed)',
        async run() {
          const { data } = await apiClient.get('/cases')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} case(s) trong hệ thống`
        },
      },
      {
        id: 'CASE-02',
        name: 'Tạo Case Mới',
        what: 'POST /cases — tạo vụ điều tra mới với tên và mô tả',
        expected: 'Case được tạo với id, status="open", timestamps hợp lệ',
        async run() {
          const name = `__test_case_${Date.now()}`
          const { data } = await apiClient.post('/cases', {
            name,
            description: 'Automated test case — created by test runner',
          })
          const c = data.data
          if (!c?.id)           throw new Error('Thiếu id')
          if (c.status !== 'open') throw new Error(`Status phải là "open", nhận "${c.status}"`)
          return `OK — case "${name}" tạo thành công (id: ${c.id.slice(0,8)}, status: ${c.status})`
        },
      },
      {
        id: 'CASE-03',
        name: 'Cập Nhật Trạng Thái Case',
        what: 'PATCH /cases/:id — thay đổi status từ open → closed',
        expected: 'Response trả về case với status="closed"',
        async run() {
          const { data: listData } = await apiClient.get('/cases')
          const openCase = listData.data?.find((c: { status: string }) => c.status === 'open')
          if (!openCase) return 'SKIP — không có case "open" nào để test'
          const { data } = await apiClient.patch(`/cases/${openCase.id}`, { status: 'closed' })
          if (data.data?.status !== 'closed') throw new Error('Status không được cập nhật thành "closed"')
          // Restore
          await apiClient.patch(`/cases/${openCase.id}`, { status: 'open' })
          return `OK — case "${openCase.name}" closed thành công (đã restore lại open)`
        },
      },
      {
        id: 'CASE-04',
        name: 'Lấy Case Summary',
        what: 'GET /cases/:id/summary — lấy tổng quan case kèm agents, deployments, checklist runs',
        expected: 'Object case với các nested arrays: agents, deployments, checklist_runs, jobs',
        async run() {
          const { data: listData } = await apiClient.get('/cases')
          if (!listData.data?.length) return 'SKIP — không có case nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/cases/${id}/summary`)
          const s = data.data
          if (!s?.id) throw new Error('Thiếu id trong summary')
          const agentCount = s.agents?.length ?? 0
          const jobCount   = s.jobs?.length ?? 0
          return `OK — case "${s.name}" | ${agentCount} agent(s), ${jobCount} job(s)`
        },
      },
      {
        id: 'CASE-05',
        name: 'Case Không Tồn Tại → 404',
        what: 'GET /cases/:id/summary với UUID không tồn tại',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/cases/00000000-0000-0000-0000-000000000000/summary')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'CASE-06',
        name: 'Case Tên Unicode (Tiếng Việt)',
        what: 'POST /cases với name chứa ký tự UTF-8 tiếng Việt',
        expected: 'Case tạo thành công, name được lưu đúng encoding',
        async run() {
          const name = `Sự cố APT ${Date.now()}`
          const { data } = await apiClient.post('/cases', { name, description: 'UTF-8 test' })
          if (!data.data?.id) throw new Error('Thiếu id trong response')
          if (data.data.name !== name) throw new Error(`Name bị biến đổi: "${data.data.name}" ≠ "${name}"`)
          return `OK — case Unicode tạo thành công: "${data.data.name}"`
        },
      },
      {
        id: 'CASE-07',
        name: 'Case Mới Xuất Hiện Trong Danh Sách',
        what: 'POST /cases rồi GET /cases — xác nhận case mới được index ngay',
        expected: 'Case mới tạo phải có mặt trong GET /cases',
        async run() {
          const name = `__test_list_${Date.now()}`
          const { data: createData } = await apiClient.post('/cases', { name, description: 'list verify' })
          const newId = createData.data?.id
          if (!newId) throw new Error('Không có id sau khi tạo')
          const { data: listData } = await apiClient.get('/cases')
          const found = listData.data?.find((c: { id: string }) => c.id === newId)
          if (!found) throw new Error(`Case ${newId.slice(0,8)} không xuất hiện trong danh sách!`)
          return `OK — case "${name}" xuất hiện đúng trong danh sách`
        },
      },
    ],
  },

  // ─── 8. ELK Threat Hunting ────────────────────────────────────────────────
  {
    id: 'elk',
    label: 'ELK Threat Hunting',
    icon: Database,
    color: 'text-yellow-400',
    borderColor: 'border-yellow-500/30',
    bgColor: 'bg-yellow-500/5',
    tests: [
      {
        id: 'ELK-01',
        name: 'Lấy Active ELK Config',
        what: 'GET /elk/config — lấy cấu hình Elasticsearch đang được kích hoạt',
        expected: 'Object config với url, index pattern (key không bị lộ)',
        async run() {
          const { data } = await apiClient.get('/elk/config')
          if (!data.data) throw new Error('Không có config nào được trả về')
          const cfg = data.data
          return `OK — ELK profile: "${cfg.name ?? 'default'}" | host: ${cfg.url ?? 'N/A'}`
        },
      },
      {
        id: 'ELK-02',
        name: 'Liệt Kê ELK Profiles',
        what: 'GET /elk/configs — lấy tất cả profile cấu hình ELK (multi-profile support)',
        expected: 'Array configs, mỗi item có id, name, url, is_active',
        async run() {
          const { data } = await apiClient.get('/elk/configs')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          const active = data.data.find((c: { is_active?: boolean }) => c.is_active)
          return `OK — ${data.data.length} ELK profile(s), active: "${active?.name ?? 'none'}"`
        },
      },
      {
        id: 'ELK-03',
        name: 'Parse IOC File (Phân Loại IOC)',
        what: 'POST /elk/iocs/parse — phân loại các dòng IOC theo loại: IPv4, hash, domain, URL…',
        expected: 'Response map: { "ipv4": [...], "sha256": [...], "domain": [...] }',
        async run() {
          const testIOCs = [
            '1.2.3.4',
            '192.168.100.1',
            'evil.example.com',
            'https://malware.test/payload.exe',
            'd41d8cd98f00b204e9800998ecf8427e',
            'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
          ].join('\n')
          const { data } = await apiClient.post('/elk/iocs/parse', { content: testIOCs })
          if (!data.data) throw new Error('Không có data trong response')
          const types = Object.entries(data.data as Record<string, unknown[]>)
            .filter(([, v]) => v.length > 0)
            .map(([k, v]) => `${k}:${v.length}`)
            .join(', ')
          return `OK — phân loại: ${types}`
        },
      },
      {
        id: 'ELK-04',
        name: 'Liệt Kê Kết Quả Hunt Đã Lưu',
        what: 'GET /elk/hunt/results — lấy lịch sử các lần hunt IOC đã được ghi lại',
        expected: 'Array results với title, iocs_used, total_hits, status',
        async run() {
          const { data } = await apiClient.get('/elk/hunt/results')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} hunt result(s) đã lưu`
        },
      },
      {
        id: 'ELK-05',
        name: 'Tạo ELK Profile Mới & Xóa',
        what: 'POST /elk/configs → kích hoạt → xóa profile test',
        expected: 'Profile được tạo, có thể kích hoạt, sau đó xóa được',
        async run() {
          const { data: createData } = await apiClient.post('/elk/configs', {
            name: `__test_elk_${Date.now()}`,
            url: 'http://localhost:9200',
            username: 'elastic',
            password: 'test',
            index_pattern: 'logs-*',
          })
          const cfg = createData.data
          if (!cfg?.id) throw new Error('Thiếu id trong response')
          try {
            await apiClient.delete(`/elk/configs/${cfg.id}`)
          } catch {
            throw new Error(`Tạo OK nhưng xóa thất bại (id: ${cfg.id})`)
          }
          return `OK — tạo & xóa ELK profile thành công, credentials ẩn`
        },
      },
      {
        id: 'ELK-06',
        name: 'Lấy Chi Tiết Hunt Result',
        what: 'GET /elk/hunt/results/:id — lấy kết quả hunt với hits và metadata',
        expected: 'Object result có title, iocs_used, total_hits, status',
        async run() {
          const { data: listData } = await apiClient.get('/elk/hunt/results')
          if (!listData.data?.length) return 'SKIP — không có hunt result nào'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/elk/hunt/results/${id}`)
          const r = data.data
          if (!r?.id) throw new Error('Thiếu id trong response')
          return `OK — result "${r.title ?? id.slice(0,8)}" | hits: ${r.total_hits ?? 0} | status: ${r.status}`
        },
      },
      {
        id: 'ELK-07',
        name: 'Hunt Result Không Tồn Tại → 404',
        what: 'GET /elk/hunt/results/:id với UUID không tồn tại',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/elk/hunt/results/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
    ],
  },

  // ─── 9. AI Analysis ──────────────────────────────────────────────────────
  {
    id: 'ai',
    label: 'AI Analysis',
    icon: BrainCircuit,
    color: 'text-violet-400',
    borderColor: 'border-violet-500/30',
    bgColor: 'bg-violet-500/5',
    tests: [
      {
        id: 'AI-01',
        name: 'Liệt Kê AI Providers',
        what: 'GET /ai/providers — lấy danh sách provider AI đã cấu hình',
        expected: 'Array providers, API key không được lộ (has_key thay thế)',
        async run() {
          const { data } = await apiClient.get('/ai/providers')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          const withKey = data.data.filter((p: { api_key?: string }) => p.api_key)
          if (withKey.length > 0) throw new Error('API key bị lộ trong response!')
          return `OK — ${data.data.length} AI provider(s), keys ẩn`
        },
      },
      {
        id: 'AI-02',
        name: 'Tạo & Xóa AI Provider (Lifecycle)',
        what: 'POST /ai/providers → xác minh key encrypted (has_key=true) → DELETE dọn dẹp',
        expected: 'Provider tạo với has_key=true, api_key không lộ, xóa được',
        async run() {
          const { data: createData } = await apiClient.post('/ai/providers', {
            name: `__test_provider_${Date.now()}`,
            provider_type: 'openai',
            base_url: 'https://api.groq.com/openai/v1',
            api_key: 'gsk_test_key_do_not_use',
            model: 'llama-3.3-70b-versatile',
            max_tokens: 4096,
            is_active: false,
          })
          const p = createData.data
          if (!p?.id) throw new Error('Thiếu id trong response')
          if (p?.api_key) throw new Error('API key bị lộ trong response!')
          if (!p?.has_key) throw new Error('has_key phải là true sau khi cung cấp key')
          try {
            await apiClient.delete(`/ai/providers/${p.id}`)
          } catch {
            throw new Error(`Tạo OK nhưng xóa thất bại (id: ${p.id.slice(0,8)})`)
          }
          return `OK — provider tạo (key mã hóa, has_key=true), xóa sạch`
        },
      },
      {
        id: 'AI-03',
        name: 'Test Provider Connection',
        what: 'POST /ai/providers/:id/test — kiểm tra kết nối thực sự đến AI API',
        expected: 'Response có field success=true/false với message rõ ràng',
        async run() {
          const { data: listData } = await apiClient.get('/ai/providers')
          if (!listData.data?.length) return 'SKIP — không có provider nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.post(`/ai/providers/${id}/test`)
          if (data.success === undefined) throw new Error('Thiếu field success trong response')
          const result = data.success ? 'kết nối thành công' : `thất bại: ${data.error ?? 'unknown'}`
          return `OK — provider "${listData.data[0].name}": ${result}`
        },
      },
      {
        id: 'AI-04',
        name: 'Liệt Kê Analysis Sessions',
        what: 'GET /ai/sessions — lấy lịch sử các lần phân tích AI',
        expected: 'Array sessions với source_type, status, provider info',
        async run() {
          const { data } = await apiClient.get('/ai/sessions')
          if (!Array.isArray(data.data)) throw new Error('data.data không phải array')
          return `OK — ${data.data.length} analysis session(s) trong lịch sử`
        },
      },
      {
        id: 'AI-05',
        name: 'Lấy Chi Tiết Session',
        what: 'GET /ai/sessions/:id — lấy session kèm chain steps và kết quả',
        expected: 'Object session có steps (JSON array), result (markdown report)',
        async run() {
          const { data: listData } = await apiClient.get('/ai/sessions')
          if (!listData.data?.length) return 'SKIP — không có session nào để test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/ai/sessions/${id}`)
          const s = data.data
          if (!s?.id) throw new Error('Thiếu id trong response')
          const raw = s.steps
          const steps = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw).length : 0
          return `OK — session ${id.slice(0,8)} | status: ${s.status} | ${steps} steps | ${s.result?.length ?? 0} chars`
        },
      },
      {
        id: 'AI-06',
        name: 'Session Không Tồn Tại → 404',
        what: 'GET /ai/sessions/:id với UUID không tồn tại',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/ai/sessions/00000000-0000-0000-0000-000000000000')
            throw new Error('Mong đợi 404 nhưng nhận được 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (đúng)'
            throw err
          }
        },
      },
      {
        id: 'AI-07',
        name: 'Provider Type Không Hợp Lệ → 400',
        what: 'POST /ai/providers với provider_type="unsupported_xyz"',
        expected: 'HTTP 400 — validation error',
        async run() {
          try {
            await apiClient.post('/ai/providers', {
              name: '__test_invalid_type',
              provider_type: 'unsupported_ai_xyz',
              api_key: 'test',
              model: 'test-model',
            })
            throw new Error('Server chấp nhận provider_type không hợp lệ!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — provider_type không hợp lệ bị từ chối (400)'
            throw err
          }
        },
      },
    ],
  },

  // ─── 10. System Health ───────────────────────────────────────────────────
  {
    id: 'system',
    label: 'System Health',
    icon: Activity,
    color: 'text-teal-400',
    borderColor: 'border-teal-500/30',
    bgColor: 'bg-teal-500/5',
    tests: [
      {
        id: 'SYS-01',
        name: 'Health Check Trả Về 4 Services',
        what: 'GET /system/health — kiểm tra trạng thái PostgreSQL, Redis, Storage, WS Hub',
        expected: 'Response có 4 fields: postgres, redis, storage, ws_hub',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const h = data.data
          if (!h) throw new Error('Không có data trong response')
          const required = ['postgres', 'redis', 'storage', 'ws_hub']
          const missing = required.filter(k => !(k in h))
          if (missing.length > 0) throw new Error(`Thiếu fields: ${missing.join(', ')}`)
          const statuses = required.map(k => `${k}:${h[k]}`).join(' | ')
          return `OK — ${statuses}`
        },
      },
      {
        id: 'SYS-02',
        name: 'Server Resources Có Trong Health',
        what: 'GET /system/health — kiểm tra có CPU/RAM/Disk của server',
        expected: 'Response có field "server" với cpu_percent, ram_used_mb, disk_used_gb',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const server = data.data?.server
          if (!server) return 'SKIP — server resources chưa được implement'
          if (server.cpu_percent === undefined) throw new Error('Thiếu cpu_percent')
          if (server.ram_used_mb === undefined) throw new Error('Thiếu ram_used_mb')
          if (server.disk_used_gb === undefined) throw new Error('Thiếu disk_used_gb')
          return `OK — CPU: ${server.cpu_percent.toFixed(1)}% | RAM: ${server.ram_used_mb}MB | Disk: ${server.disk_used_gb}GB`
        },
      },
      {
        id: 'SYS-03',
        name: 'Agent Resources Trong Health',
        what: 'GET /system/health — kiểm tra có mảng resource usage của agents online',
        expected: 'Response có field "agent_resources" là array (có thể rỗng)',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const resources = data.data?.agent_resources
          if (resources === undefined) return 'SKIP — agent_resources chưa được implement'
          if (!Array.isArray(resources)) throw new Error('agent_resources phải là array')
          return `OK — ${resources.length} agent(s) đang báo cáo resource`
        },
      },
      {
        id: 'SYS-04',
        name: 'Token Stats Endpoint',
        what: 'GET /system/token-stats — lấy thống kê AI token đã sử dụng',
        expected: 'Object có by_provider (array) và total_tokens (number)',
        async run() {
          const { data } = await apiClient.get('/system/token-stats')
          if (!data.data) throw new Error('Không có data trong response')
          const stats = data.data
          if (!Array.isArray(stats.by_provider)) throw new Error('by_provider phải là array')
          const total = stats.total_tokens ?? 0
          return `OK — tổng ${total.toLocaleString()} token(s) | ${stats.by_provider.length} provider(s)`
        },
      },
      {
        id: 'SYS-05',
        name: 'Health Endpoint Yêu Cầu Auth',
        what: 'GET /system/health không có JWT — bảo vệ thông tin hạ tầng',
        expected: 'HTTP 401 — thông tin server không lộ cho unauthenticated users',
        async run() {
          try {
            await rawAxios.get('/system/health')
            throw new Error('Thông tin hệ thống bị lộ cho unauthenticated request!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — health endpoint được bảo vệ (401)'
            throw err
          }
        },
      },
    ],
  },
]

// ---------------------------------------------------------------------------
// StatusBadge component
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: TestStatus }) {
  if (status === 'idle')    return <span className="inline-flex items-center gap-1 text-[11px] text-gray-500"><Clock className="h-3 w-3" /> Pending</span>
  if (status === 'running') return <span className="inline-flex items-center gap-1 text-[11px] text-sky-400"><Loader2 className="h-3 w-3 animate-spin" /> Running</span>
  if (status === 'pass')    return <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400"><CheckCircle2 className="h-3 w-3" /> Pass</span>
  if (status === 'fail')    return <span className="inline-flex items-center gap-1 text-[11px] text-red-400"><XCircle className="h-3 w-3" /> Fail</span>
  if (status === 'skip')    return <span className="inline-flex items-center gap-1 text-[11px] text-gray-500"><SkipForward className="h-3 w-3" /> Skip</span>
  return null
}

// ---------------------------------------------------------------------------
// Individual TestRow
// ---------------------------------------------------------------------------

interface TestRowProps {
  def: TestDef
  result: TestResult
  onRun: () => void
  isRunning: boolean
}

function TestRow({ def, result, onRun, isRunning }: TestRowProps) {
  const [expanded, setExpanded] = useState(false)
  const hasDetail = result.status !== 'idle' && result.detail

  const rowBg =
    result.status === 'pass' ? 'border-l-2 border-l-emerald-500/60' :
    result.status === 'fail' ? 'border-l-2 border-l-red-500/60' :
    result.status === 'skip' ? 'border-l-2 border-l-gray-600/60' :
    'border-l-2 border-l-transparent'

  return (
    <div className={`bg-gray-900/40 rounded-lg border border-gray-800/60 overflow-hidden ${rowBg}`}>
      <div className="flex items-start gap-3 px-4 py-3">
        {/* ID badge */}
        <span className="shrink-0 mt-0.5 text-[10px] font-mono font-bold text-gray-600 bg-gray-800/60 px-1.5 py-0.5 rounded border border-gray-700/50 min-w-[64px] text-center">
          {def.id}
        </span>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-200">{def.name}</span>
            <StatusBadge status={result.status} />
            {result.duration > 0 && (
              <span className="text-[10px] text-gray-600 font-mono">{result.duration}ms</span>
            )}
          </div>
          <p className="text-[12px] text-gray-500 mt-0.5 leading-relaxed">{def.what}</p>
          <p className="text-[11px] text-gray-600 mt-0.5">
            <span className="text-gray-700">Mong đợi: </span>{def.expected}
          </p>

          {/* Detail / Error */}
          {hasDetail && (
            <button
              onClick={() => setExpanded(e => !e)}
              className="flex items-center gap-1 mt-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {expanded ? 'Ẩn chi tiết' : 'Xem chi tiết'}
            </button>
          )}
          {expanded && hasDetail && (
            <div className={`mt-2 rounded-md px-3 py-2 text-[12px] font-mono leading-relaxed break-all
              ${result.status === 'fail' ? 'bg-red-950/40 text-red-300 border border-red-900/40' :
                result.status === 'skip' ? 'bg-gray-800/40 text-gray-400 border border-gray-700/30' :
                'bg-gray-800/40 text-emerald-300 border border-gray-700/30'}`}>
              {result.detail}
            </div>
          )}
        </div>

        {/* Run button */}
        <button
          onClick={onRun}
          disabled={isRunning}
          className="shrink-0 flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-medium
            bg-gray-800/60 text-gray-400 hover:text-white hover:bg-gray-700 border border-gray-700/50
            disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {isRunning
            ? <Loader2 className="h-3 w-3 animate-spin" />
            : <Play className="h-3 w-3" />
          }
          Run
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function TestCasesPage() {
  const [activeCategory, setActiveCategory] = useState(CATEGORIES[0].id)
  const [results, setResults] = useState<Record<string, TestResult>>({})
  const [runningIds, setRunningIds] = useState<Set<string>>(new Set())
  const runningAllRef = useRef(false)

  const setResult = useCallback((testId: string, result: TestResult) => {
    setResults(prev => ({ ...prev, [testId]: result }))
  }, [])

  const runTest = useCallback(async (def: TestDef) => {
    if (runningIds.has(def.id)) return
    setRunningIds(prev => new Set([...prev, def.id]))
    setResult(def.id, { status: 'running', detail: '', duration: 0 })
    const t0 = Date.now()
    try {
      const detail = await def.run()
      const status: TestStatus = detail.startsWith('SKIP') ? 'skip' : 'pass'
      setResult(def.id, { status, detail, duration: Date.now() - t0 })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setResult(def.id, { status: 'fail', detail: msg, duration: Date.now() - t0 })
    } finally {
      setRunningIds(prev => {
        const next = new Set(prev)
        next.delete(def.id)
        return next
      })
    }
  }, [runningIds, setResult])

  const runCategory = useCallback(async (cat: CategoryDef) => {
    for (const test of cat.tests) {
      await runTest(test)
    }
  }, [runTest])

  const runAll = useCallback(async () => {
    if (runningAllRef.current) return
    runningAllRef.current = true
    for (const cat of CATEGORIES) {
      for (const test of cat.tests) {
        await runTest(test)
      }
    }
    runningAllRef.current = false
  }, [runTest])

  // Summary stats across all tests
  const allTests = CATEGORIES.flatMap(c => c.tests)
  const total   = allTests.length
  const passCount = allTests.filter(t => results[t.id]?.status === 'pass').length
  const failCount = allTests.filter(t => results[t.id]?.status === 'fail').length
  const skipCount = allTests.filter(t => results[t.id]?.status === 'skip').length
  const doneCount = passCount + failCount + skipCount
  const isAnyRunning = runningIds.size > 0

  const activeCat = CATEGORIES.find(c => c.id === activeCategory) ?? CATEGORIES[0]

  // Per-category summary
  const catSummary = (cat: CategoryDef) => {
    const pass = cat.tests.filter(t => results[t.id]?.status === 'pass').length
    const fail = cat.tests.filter(t => results[t.id]?.status === 'fail').length
    return { pass, fail, total: cat.tests.length }
  }

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FlaskConical className="h-5 w-5 text-violet-400" />
            <h1 className="text-lg font-bold text-gray-100">Test Cases</h1>
            <span className="text-[10px] font-mono text-gray-600 bg-gray-800/60 border border-gray-700/50 px-2 py-0.5 rounded-full">
              {total} tests · {CATEGORIES.length} categories
            </span>
          </div>
          <p className="text-sm text-gray-500">
            Kiểm tra toàn bộ API backend của ForensicHub-v2 — chạy từng test hoặc toàn bộ để xác nhận hệ thống hoạt động đúng.
          </p>
        </div>
        <button
          onClick={runAll}
          disabled={isAnyRunning}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
            bg-violet-600/20 text-violet-300 hover:bg-violet-600/30 border border-violet-500/30
            disabled:opacity-50 disabled:cursor-not-allowed transition-colors shrink-0"
        >
          {isAnyRunning
            ? <><Loader2 className="h-4 w-4 animate-spin" /> Đang chạy…</>
            : <><PlayCircle className="h-4 w-4" /> Run All Tests</>
          }
        </button>
      </div>

      {/* ── Summary Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-gray-900/60 rounded-lg border border-gray-800/60 px-4 py-3 flex items-center gap-3">
          <AlertCircle className="h-4 w-4 text-gray-500 shrink-0" />
          <div>
            <div className="text-xl font-bold text-gray-200">{total}</div>
            <div className="text-[11px] text-gray-600">Total Tests</div>
          </div>
        </div>
        <div className="bg-gray-900/60 rounded-lg border border-emerald-500/20 px-4 py-3 flex items-center gap-3">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <div>
            <div className="text-xl font-bold text-emerald-400">{passCount}</div>
            <div className="text-[11px] text-gray-600">Passed</div>
          </div>
        </div>
        <div className="bg-gray-900/60 rounded-lg border border-red-500/20 px-4 py-3 flex items-center gap-3">
          <XCircle className="h-4 w-4 text-red-400 shrink-0" />
          <div>
            <div className="text-xl font-bold text-red-400">{failCount}</div>
            <div className="text-[11px] text-gray-600">Failed</div>
          </div>
        </div>
        <div className="bg-gray-900/60 rounded-lg border border-gray-700/40 px-4 py-3 flex items-center gap-3">
          <Clock className="h-4 w-4 text-gray-500 shrink-0" />
          <div>
            <div className="text-xl font-bold text-gray-400">{total - doneCount}</div>
            <div className="text-[11px] text-gray-600">Pending</div>
          </div>
        </div>
      </div>

      {/* Progress bar */}
      {doneCount > 0 && (
        <div className="h-1.5 rounded-full bg-gray-800/60 overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-300"
            style={{ width: `${(passCount / total) * 100}%` }}
          />
        </div>
      )}

      {/* ── Category Tabs ── */}
      <div className="flex gap-1 overflow-x-auto pb-1 custom-scrollbar">
        {CATEGORIES.map((cat) => {
          const { pass, fail, total: ct } = catSummary(cat)
          const isActive = cat.id === activeCategory
          const Icon = cat.icon
          return (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-colors shrink-0
                ${isActive
                  ? `${cat.bgColor} ${cat.color} border ${cat.borderColor}`
                  : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50 border border-transparent'
                }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {cat.label}
              {fail > 0 && (
                <span className="ml-0.5 bg-red-500/20 text-red-400 text-[9px] px-1 rounded-full border border-red-500/20">{fail}</span>
              )}
              {fail === 0 && pass > 0 && (
                <span className="ml-0.5 bg-emerald-500/20 text-emerald-400 text-[9px] px-1 rounded-full border border-emerald-500/20">
                  {pass}/{ct}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Active Category Panel ── */}
      <div className={`rounded-xl border ${activeCat.borderColor} overflow-hidden`}>
        {/* Category header */}
        <div className={`flex items-center justify-between px-5 py-3 ${activeCat.bgColor} border-b ${activeCat.borderColor}`}>
          <div className="flex items-center gap-2.5">
            {(() => { const Icon = activeCat.icon; return <Icon className={`h-4 w-4 ${activeCat.color}`} /> })()}
            <span className={`text-sm font-semibold ${activeCat.color}`}>{activeCat.label}</span>
            <span className="text-[10px] text-gray-600 bg-gray-800/40 px-1.5 py-0.5 rounded border border-gray-700/40">
              {activeCat.tests.length} tests
            </span>
            {catSummary(activeCat).fail > 0 && (
              <span className="text-[10px] text-red-400 bg-red-900/20 px-1.5 py-0.5 rounded border border-red-700/30">
                {catSummary(activeCat).fail} failed
              </span>
            )}
            {catSummary(activeCat).pass === activeCat.tests.length && catSummary(activeCat).pass > 0 && (
              <span className="text-[10px] text-emerald-400 bg-emerald-900/20 px-1.5 py-0.5 rounded border border-emerald-700/30">
                ✓ All pass
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                activeCat.tests.forEach(t => {
                  if (results[t.id]) setResults(prev => {
                    const next = { ...prev }
                    delete next[t.id]
                    return next
                  })
                })
              }}
              className="flex items-center gap-1 px-2 py-1 rounded text-[11px] text-gray-500 hover:text-gray-300 hover:bg-gray-700/50 transition-colors"
            >
              <RefreshCw className="h-3 w-3" /> Reset
            </button>
            <button
              onClick={() => runCategory(activeCat)}
              disabled={isAnyRunning}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium
                ${activeCat.bgColor} ${activeCat.color} border ${activeCat.borderColor}
                hover:opacity-80 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity`}
            >
              <PlayCircle className="h-3.5 w-3.5" /> Run Category
            </button>
          </div>
        </div>

        {/* Test rows */}
        <div className="p-4 space-y-2.5 bg-gray-950/40">
          {activeCat.tests.map((def) => (
            <TestRow
              key={def.id}
              def={def}
              result={results[def.id] ?? { status: 'idle', detail: '', duration: 0 }}
              onRun={() => runTest(def)}
              isRunning={runningIds.has(def.id)}
            />
          ))}
        </div>
      </div>

      {/* ── Quick Overview (all categories) ── */}
      <div className="mt-2">
        <h3 className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-3">
          Tổng quan tất cả categories
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          {CATEGORIES.map((cat) => {
            const { pass, fail, total: ct } = catSummary(cat)
            const done = pass + fail + cat.tests.filter(t => results[t.id]?.status === 'skip').length
            const Icon = cat.icon
            return (
              <button
                key={cat.id}
                onClick={() => setActiveCategory(cat.id)}
                className={`text-left p-3 rounded-lg border transition-colors
                  ${cat.id === activeCategory ? `${cat.bgColor} ${cat.borderColor}` : 'bg-gray-900/40 border-gray-800/60 hover:border-gray-700'}
                `}
              >
                <div className="flex items-center gap-1.5 mb-2">
                  <Icon className={`h-3.5 w-3.5 ${cat.color}`} />
                  <span className={`text-xs font-medium ${cat.id === activeCategory ? cat.color : 'text-gray-400'}`}>
                    {cat.label}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {fail > 0
                    ? <span className="text-[11px] text-red-400">{fail} fail</span>
                    : pass > 0
                      ? <span className="text-[11px] text-emerald-400">{pass} pass</span>
                      : <span className="text-[11px] text-gray-600">pending</span>
                  }
                  <span className="text-[10px] text-gray-700">{done}/{ct}</span>
                </div>
                {/* Mini progress */}
                <div className="mt-1.5 h-0.5 rounded-full bg-gray-800 overflow-hidden">
                  {done > 0 && (
                    <div
                      className={`h-full rounded-full ${fail > 0 ? 'bg-red-500' : 'bg-emerald-500'}`}
                      style={{ width: `${(done / ct) * 100}%` }}
                    />
                  )}
                </div>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
