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
  what: string      // One-line description: what this test case checks
  expected: string  // Expected result
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
        what: 'Call GET /auth/me with a valid JWT token from the current session',
        expected: 'Response returns a user object with email, role, id',
        async run() {
          const { data } = await apiClient.get('/auth/me')
          if (!data.data?.email) throw new Error('Missing email field in response')
          if (!data.data?.role)  throw new Error('Missing role field in response')
          return `OK — user: ${data.data.email} | role: ${data.data.role}`
        },
      },
      {
        id: 'AUTH-02',
        name: 'Access Endpoint Without Token',
        what: 'Call GET /auth/me WITHOUT an Authorization header',
        expected: 'Server must reject with HTTP 401 Unauthorized',
        async run() {
          try {
            await rawAxios.get('/auth/me')
            throw new Error('Expected 401 but got 200 — endpoint is not protected!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — 401 Unauthorized (as expected)'
            throw err
          }
        },
      },
      {
        id: 'AUTH-03',
        name: 'Login With Wrong Credentials',
        what: 'POST /auth/login with an email and password that do not exist',
        expected: 'HTTP 401 — no JWT token returned',
        async run() {
          try {
            await rawAxios.post('/auth/login', {
              email: 'nonexistent_test_user@invalid.xyz',
              password: 'wrong_password_12345',
            })
            throw new Error('Expected 401 but got 200 — security hole!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — 401 Unauthorized (credentials rejected)'
            throw err
          }
        },
      },
      {
        id: 'AUTH-04',
        name: 'Auth Middleware Applies To Every Route',
        what: 'Call GET /agents without a token — check the global auth middleware',
        expected: 'HTTP 401, no agent data leaked',
        async run() {
          try {
            await rawAxios.get('/agents')
            throw new Error('Expected 401 but got 200!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — /agents is properly protected'
            throw err
          }
        },
      },
      {
        id: 'AUTH-05',
        name: 'Successful Login',
        what: 'POST /auth/login with default admin credentials — get a valid JWT token',
        expected: 'HTTP 200, response contains a token (JWT) and user info',
        async run() {
          const { data } = await rawAxios.post('/auth/login', {
            email: 'admin@forensichub.local',
            password: 'Admin@123456',
          })
          if (!data.token) throw new Error('Missing token in response')
          if (!data.user?.email) throw new Error('Missing user.email in response')
          return `OK — login succeeded | user: ${data.user.email} | token: ${String(data.token).slice(0, 20)}…`
        },
      },
      {
        id: 'AUTH-06',
        name: 'Login Missing Email Field → 400',
        what: 'POST /auth/login sending only a password, no email',
        expected: 'HTTP 400 or 401 — validation or auth error',
        async run() {
          try {
            await rawAxios.post('/auth/login', { password: 'Admin@123456' })
            throw new Error('Server accepted a request without email — needs validation!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 401)
              return `OK — server rejected the request without email (${e.response.status})`
            throw err
          }
        },
      },
      {
        id: 'AUTH-07',
        name: 'Login Empty Body → Error',
        what: 'POST /auth/login with an empty {} body',
        expected: 'HTTP 400 or 401, server does not crash',
        async run() {
          try {
            await rawAxios.post('/auth/login', {})
            throw new Error('Server accepted an empty body — security hole!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 401)
              return `OK — server rejected the empty body (${e.response.status})`
            throw err
          }
        },
      },
      {
        id: 'AUTH-08',
        name: 'Forged JWT Rejected',
        what: 'Call GET /auth/me with a JWT signed using the wrong secret',
        expected: 'HTTP 401 — server verifies the JWT signature',
        async run() {
          const fakeJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ.invalid_signature_here'
          try {
            await rawAxios.get('/auth/me', { headers: { Authorization: `Bearer ${fakeJWT}` } })
            throw new Error('Server accepted a forged JWT — critical security hole!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — forged JWT rejected (401)'
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
        name: 'List All Agents',
        what: 'GET /agents — get the list of registered agents',
        expected: 'Response is an array (may be empty), each item has id, name, status',
        async run() {
          const { data } = await apiClient.get('/agents')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} agent(s) in the system`
        },
      },
      {
        id: 'AGENT-02',
        name: 'Create & Delete Agent (Lifecycle)',
        what: 'POST /agents to create → verify id/token → DELETE to remove',
        expected: 'Agent created with a valid token, then deleted successfully',
        async run() {
          const name = `__test_agent_${Date.now()}`
          const { data: createData } = await apiClient.post('/agents', {
            name,
            description: 'Automated test agent — safe to delete',
          })
          const agent = createData.data
          if (!agent?.id)    throw new Error('No id in response')
          if (!agent?.token) throw new Error('No token in response')
          try {
            await apiClient.delete(`/agents/${agent.id}`)
          } catch {
            throw new Error(`Created OK (${agent.id.slice(0,8)}) but delete failed`)
          }
          return `OK — created agent "${name}", deleted successfully`
        },
      },
      {
        id: 'AGENT-03',
        name: 'Get Agent Installer Config',
        what: 'GET /agents/:id/installer — get the JSON config to deploy an agent',
        expected: 'Response contains agent_id, server_url',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — no agent to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/agents/${id}/installer`)
          const cfg = data.data
          if (!cfg?.agent_id) throw new Error('Missing agent_id')
          if (!cfg?.server_url) throw new Error('Missing server_url')
          return `OK — installer config for agent "${cfg.agent_name}" at ${cfg.server_url}`
        },
      },
      {
        id: 'AGENT-04',
        name: 'Update Agent Description',
        what: 'PATCH /agents/:id — update the description field',
        expected: 'Response returns the agent with the updated description',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — no agent to test'
          const id = listData.data[0].id
          const newDesc = `Test update at ${new Date().toISOString()}`
          const { data } = await apiClient.patch(`/agents/${id}`, { description: newDesc })
          if (data.data?.description !== newDesc) throw new Error('Description was not updated')
          return `OK — description updated for agent ${id.slice(0,8)}`
        },
      },
      {
        id: 'AGENT-05',
        name: 'Browse Agent Filesystem',
        what: 'GET /agents/:id/fs?path=/ — list the root directory on an online agent',
        expected: 'Response is an array of entries (file/directory names)',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          const online = listData.data?.find((a: { status: string }) => a.status === 'online')
          if (!online) return 'SKIP — no online agent to test the filesystem'
          const { data } = await apiClient.get(`/agents/${online.id}/fs`, { params: { path: '/' } })
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} entries in the filesystem of agent "${online.name}"`
        },
      },
      {
        id: 'AGENT-06',
        name: 'Empty Agent Name Rejected',
        what: 'POST /agents with name="" — check required-field validation',
        expected: 'HTTP 400 Bad Request',
        async run() {
          try {
            await apiClient.post('/agents', { name: '', description: 'validation test' })
            throw new Error('Server accepted an empty name — needs validation!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — empty name rejected (400)'
            throw err
          }
        },
      },
      {
        id: 'AGENT-07',
        name: 'Agent Does Not Exist → 404',
        what: 'GET /agents/:id with a UUID not in the DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/agents/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'AGENT-08',
        name: 'Token Not Leaked In List',
        what: 'GET /agents — check the "token" field is absent from the list response',
        expected: 'No item has a token field (security check)',
        async run() {
          const { data: listData } = await apiClient.get('/agents')
          if (!listData.data?.length) return 'SKIP — no agent to check'
          const withToken = listData.data.filter((a: { token?: string }) => a.token)
          if (withToken.length > 0) throw new Error(`${withToken.length} agent(s) leaked a token in the response!`)
          return `OK — no token leaked across ${listData.data.length} agent(s)`
        },
      },
      {
        id: 'AGENT-09',
        name: 'Download Agent Binary (Windows)',
        what: 'GET /agents/binary/windows — download agent binary cho Windows',
        expected: 'HTTP 200 with the binary file, or 404 if the binary is not built',
        async run() {
          try {
            const { status } = await apiClient.get('/agents/binary/windows', { responseType: 'blob' })
            if (status !== 200) throw new Error(`Status ${status}`)
            return 'OK — Windows agent binary endpoint responded 200'
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'SKIP — binary not built/uploaded yet'
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
        name: 'List All Tools',
        what: 'GET /tools — get the list of all forensic tools',
        expected: 'Array of tools, each item has id, name, category, platform',
        async run() {
          const { data } = await apiClient.get('/tools')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} tool(s) in the library`
        },
      },
      {
        id: 'TOOL-02',
        name: 'Filter Tools By Platform',
        what: 'GET /tools?platform=windows — only Windows tools',
        expected: 'Array contains only tools with platform="windows" or "both"',
        async run() {
          const { data } = await apiClient.get('/tools', { params: { platform: 'windows' } })
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} Windows tool(s)`
        },
      },
      {
        id: 'TOOL-03',
        name: 'Filter Tools By Category',
        what: 'GET /tools?category=memory — tools in the memory-analysis category',
        expected: 'Array contains only tools with category="memory"',
        async run() {
          const { data } = await apiClient.get('/tools', { params: { category: 'memory' } })
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} memory tool(s)`
        },
      },
      {
        id: 'TOOL-04',
        name: 'Get Tool Details',
        what: 'GET /tools/:id — get the full metadata of a specific tool',
        expected: 'Tool object with id, name, category, platform, default_args',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — no tool in the system'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/tools/${id}`)
          if (!data.data?.name) throw new Error('Missing name field in response')
          return `OK — tool "${data.data.name}" (${data.data.category}/${data.data.platform})`
        },
      },
      {
        id: 'TOOL-05',
        name: 'Tool Does Not Exist → 404',
        what: 'GET /tools/:id with a UUID not in the DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/tools/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'TOOL-06',
        name: 'Update Tool Metadata',
        what: 'PUT /tools/:id — update the description of an existing tool',
        expected: 'Response returns the tool with updated metadata',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — no tool to test'
          const tool = listData.data[0]
          const newDesc = `[Test] Updated at ${new Date().toISOString()}`
          const { data } = await apiClient.put(`/tools/${tool.id}`, {
            name: tool.name,
            description: newDesc,
            category: tool.category,
            platform: tool.platform,
          })
          if (!data.data) throw new Error('No data in response')
          return `OK — tool "${tool.name}" description updated successfully`
        },
      },
      {
        id: 'TOOL-07',
        name: 'Server File Path Not Leaked',
        what: 'GET /tools/:id — check the response has no absolute server paths',
        expected: 'No "/var/", "C:\\\\", "/home/" in the response',
        async run() {
          const { data: listData } = await apiClient.get('/tools')
          if (!listData.data?.length) return 'SKIP — no tool to check'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/tools/${id}`)
          const str = JSON.stringify(data.data ?? {})
          if (str.includes('/var/') || str.includes('C:\\\\') || str.includes('/home/'))
            throw new Error('Server file path leaked in the response!')
          return 'OK — no absolute server path found in the response'
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
        name: 'List All Jobs',
        what: 'GET /jobs — get the list of all tool-execution jobs',
        expected: 'Array of jobs, each item has id, status, agent_id, tool_id',
        async run() {
          const { data } = await apiClient.get('/jobs')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} job(s) in the system`
        },
      },
      {
        id: 'JOB-02',
        name: 'Filter Jobs By Status=done',
        what: 'GET /jobs?status=done — only completed jobs',
        expected: 'Every item in the array must have status="done"',
        async run() {
          const { data } = await apiClient.get('/jobs', { params: { status: 'done' } })
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          const mismatch = data.data.filter((j: { status: string }) => j.status !== 'done')
          if (mismatch.length > 0) throw new Error(`${mismatch.length} job(s) not "done"`)
          return `OK — ${data.data.length} job(s) with status=done`
        },
      },
      {
        id: 'JOB-03',
        name: 'Get Job Details',
        what: 'GET /jobs/:id — full info with agent and tool preloaded',
        expected: 'Job object has id, status, tool.name, agent.name',
        async run() {
          const { data: listData } = await apiClient.get('/jobs')
          if (!listData.data?.length) return 'SKIP — no job to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/jobs/${id}`)
          const job = data.data
          if (!job?.id) throw new Error('Missing id in response')
          return `OK — job ${id.slice(0,8)} | status: ${job.status} | tool: ${job.tool?.name ?? 'N/A'}`
        },
      },
      {
        id: 'JOB-04',
        name: 'Get Job Artifact Content',
        what: 'GET /jobs/:id/artifact/content — get the result artifact file content',
        expected: 'Text content of the artifact file if the job has an artifact_path',
        async run() {
          const { data: listData } = await apiClient.get('/jobs', { params: { status: 'done' } })
          const withArtifact = listData.data?.find((j: { artifact_path?: string }) => j.artifact_path)
          if (!withArtifact) return 'SKIP — no completed job has an artifact'
          const { data } = await apiClient.get(`/jobs/${withArtifact.id}/artifact/content`)
          if (typeof data !== 'string' && typeof data !== 'object') throw new Error('Invalid response')
          return `OK — artifact content of job ${withArtifact.id.slice(0,8)} (${String(data).length} bytes)`
        },
      },
      {
        id: 'JOB-05',
        name: 'Filter Jobs By Agent',
        what: 'GET /jobs?agent_id=:id — only jobs of a specific agent',
        expected: 'Every item in the array must have a matching agent_id',
        async run() {
          const { data: agentData } = await apiClient.get('/agents')
          if (!agentData.data?.length) return 'SKIP — no agent'
          const agentId = agentData.data[0].id
          const { data } = await apiClient.get('/jobs', { params: { agent_id: agentId } })
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          const mismatch = data.data.filter((j: { agent_id: string }) => j.agent_id !== agentId)
          if (mismatch.length > 0) throw new Error(`${mismatch.length} job(s) not belonging to agent ${agentId.slice(0,8)}`)
          return `OK — ${data.data.length} job(s) of agent ${agentId.slice(0,8)}`
        },
      },
      {
        id: 'JOB-06',
        name: 'Job Does Not Exist → 404',
        what: 'GET /jobs/:id with a UUID not in the DB',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/jobs/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'JOB-07',
        name: 'Stop A Completed Job → 400',
        what: 'POST /jobs/:id/stop on a status=done job — cannot stop a finished job',
        expected: 'HTTP 400 Bad Request',
        async run() {
          const { data: listData } = await apiClient.get('/jobs', { params: { status: 'done' } })
          if (!listData.data?.length) return 'SKIP — no completed job to test'
          const id = listData.data[0].id
          try {
            await apiClient.post(`/jobs/${id}/stop`)
            throw new Error('Server allowed stopping a completed job — incorrect!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return `OK — cannot stop a completed job (400)`
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
        name: 'List Checklist Runs',
        what: 'GET /checklist/runs — history of evidence-collection runs',
        expected: 'Array of runs, each item has id, agent_id, status, created_at',
        async run() {
          const { data } = await apiClient.get('/checklist/runs')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} checklist run(s) in history`
        },
      },
      {
        id: 'CHK-02',
        name: 'Get Checklist Run Details',
        what: 'GET /checklist/runs/:id — run with batches and per-command output',
        expected: 'Run object has id, a batches array, each batch has a status',
        async run() {
          const { data: listData } = await apiClient.get('/checklist/runs')
          if (!listData.data?.length) return 'SKIP — no run to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/checklist/runs/${id}`)
          const run = data.data
          if (!run?.id) throw new Error('Missing id in response')
          const batchCount = run.batches?.length ?? 0
          return `OK — run ${id.slice(0,8)} | ${batchCount} batch(es) | status: ${run.status}`
        },
      },
      {
        id: 'CHK-03',
        name: 'Batch Fields Complete',
        what: 'Get run detail → check the first batch has id, status, batch_key',
        expected: 'Batch has id, batch_key, batch_label, status',
        async run() {
          const { data: listData } = await apiClient.get('/checklist/runs')
          if (!listData.data?.length) return 'SKIP — no run'
          const { data: runDetail } = await apiClient.get(`/checklist/runs/${listData.data[0].id}`)
          const batch = runDetail.data?.batches?.[0]
          if (!batch) return 'SKIP — run has no batches'
          if (!batch.id) throw new Error('Batch missing id')
          if (!batch.status) throw new Error('Batch missing status')
          return `OK — batch "${batch.batch_label ?? batch.batch_key}" | status: ${batch.status}`
        },
      },
      {
        id: 'CHK-04',
        name: 'Run Does Not Exist → 404',
        what: 'GET /checklist/runs/:id with a non-existent UUID',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/checklist/runs/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'CHK-05',
        name: 'Detect Runs By Platform',
        what: 'GET /checklist/runs — check win/linux platform is distinguishable',
        expected: 'Find a run with a platform field (win or linux)',
        async run() {
          const { data } = await apiClient.get('/checklist/runs')
          if (!data.data?.length) return 'SKIP — no run'
          const withPlatform = data.data.filter((r: { platform?: string }) => r.platform)
          if (!withPlatform.length) return 'SKIP — no run has a platform field'
          const platforms = [...new Set(withPlatform.map((r: { platform: string }) => r.platform))].join(', ')
          return `OK — detected platform(s): ${platforms} across ${data.data.length} run(s)`
        },
      },
      {
        id: 'CHK-06',
        name: 'Create Run With Non-existent Agent → Error',
        what: 'POST /checklist/run with an agent_id UUID not in the DB',
        expected: 'HTTP 400 or 404 — cannot run with an invalid agent',
        async run() {
          try {
            await apiClient.post('/checklist/run', {
              agent_id: '00000000-0000-0000-0000-000000000000',
              platform: 'win',
              label: 'Test invalid agent',
              analyst: 'tester',
            })
            throw new Error('Server allowed creating a run with a non-existent agent!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400 || e.response?.status === 404 || e.response?.status === 503)
              return `OK — rejected with an invalid agent (${e.response.status})`
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
        name: 'List Hunting Scenarios',
        what: 'GET /hunting/scenarios — list all attack/investigation scenarios',
        expected: 'Array of scenarios, each item has id, name, tools (preloaded)',
        async run() {
          const { data } = await apiClient.get('/hunting/scenarios')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} hunting scenario(s)`
        },
      },
      {
        id: 'HUNT-02',
        name: 'Create & Delete Scenario (Lifecycle)',
        what: 'POST /hunting/scenarios to create → GET it back → DELETE',
        expected: 'Scenario created with an id, then fully removed from the DB',
        async run() {
          const name = `__test_scenario_${Date.now()}`
          const { data: createData } = await apiClient.post('/hunting/scenarios', {
            name,
            description: 'Automated test scenario — safe to delete',
          })
          const sc = createData.data
          if (!sc?.id) throw new Error('No id in response')
          try {
            await apiClient.delete(`/hunting/scenarios/${sc.id}`)
          } catch {
            throw new Error(`Created OK but DELETE failed (id: ${sc.id.slice(0,8)})`)
          }
          return `OK — created scenario "${name}", deleted successfully`
        },
      },
      {
        id: 'HUNT-03',
        name: 'Attach Tool To Scenario',
        what: 'POST /hunting/scenarios/:id/tools with tool_id — link a tool to the scenario',
        expected: 'Scenario updated with the attached tool',
        async run() {
          const { data: toolsData } = await apiClient.get('/tools')
          if (!toolsData.data?.length) return 'SKIP — no tool to attach'
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
            if (!getBack.data?.tools?.length) throw new Error('Tool did not appear after attaching')
            return `OK — attached tool "${toolsData.data[0].name}" to the scenario`
          } finally {
            try { await apiClient.delete(`/hunting/scenarios/${sc.id}`) } catch {}
          }
        },
      },
      {
        id: 'HUNT-04',
        name: 'List Deployments',
        what: 'GET /hunting/deployments — history of scenario deployments to agents',
        expected: 'Array of deployments, each item has a scenario and linked jobs',
        async run() {
          const { data } = await apiClient.get('/hunting/deployments')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} deployment(s) in history`
        },
      },
      {
        id: 'HUNT-05',
        name: 'Update Scenario',
        what: 'PUT /hunting/scenarios/:id — change the scenario description',
        expected: 'Response returns the scenario with updated metadata',
        async run() {
          const { data: listData } = await apiClient.get('/hunting/scenarios')
          if (!listData.data?.length) return 'SKIP — no scenario to test'
          const sc = listData.data[0]
          const { data } = await apiClient.put(`/hunting/scenarios/${sc.id}`, {
            name: sc.name,
            description: `Updated at ${new Date().toISOString()}`,
          })
          if (!data.data) throw new Error('No data in response')
          return `OK — scenario "${sc.name}" updated successfully`
        },
      },
      {
        id: 'HUNT-06',
        name: 'Scenario Does Not Exist → 404',
        what: 'GET /hunting/scenarios/:id with a non-existent UUID',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/hunting/scenarios/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'HUNT-07',
        name: 'Empty Scenario Name → 400',
        what: 'POST /hunting/scenarios with name="" — check required-field validation',
        expected: 'HTTP 400 Bad Request',
        async run() {
          try {
            await apiClient.post('/hunting/scenarios', { name: '', description: 'test' })
            throw new Error('Server accepted an empty name — needs validation!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — empty name rejected (400)'
            throw err
          }
        },
      },
      {
        id: 'HUNT-08',
        name: 'Get Deployment Detail',
        what: 'GET /hunting/deployments/:id — deployment with scenario and jobs',
        expected: 'Deployment object has id, scenario, jobs array',
        async run() {
          const { data: listData } = await apiClient.get('/hunting/deployments')
          if (!listData.data?.length) return 'SKIP — no deployment to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/hunting/deployments/${id}`)
          const dep = data.data
          if (!dep?.id) throw new Error('Missing id in response')
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
        name: 'List All Cases',
        what: 'GET /cases — get the list of investigation cases',
        expected: 'Array of cases, each item has id, name, status (open/closed)',
        async run() {
          const { data } = await apiClient.get('/cases')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} case(s) in the system`
        },
      },
      {
        id: 'CASE-02',
        name: 'Create New Case',
        what: 'POST /cases — create a new investigation case with a name and description',
        expected: 'Case created with an id, status="open", valid timestamps',
        async run() {
          const name = `__test_case_${Date.now()}`
          const { data } = await apiClient.post('/cases', {
            name,
            description: 'Automated test case — created by test runner',
          })
          const c = data.data
          if (!c?.id)           throw new Error('Missing id')
          if (c.status !== 'open') throw new Error(`Status must be "open", got "${c.status}"`)
          return `OK — case "${name}" created successfully (id: ${c.id.slice(0,8)}, status: ${c.status})`
        },
      },
      {
        id: 'CASE-03',
        name: 'Update Case Status',
        what: 'PATCH /cases/:id — change status from open → closed',
        expected: 'Response returns the case with status="closed"',
        async run() {
          const { data: listData } = await apiClient.get('/cases')
          const openCase = listData.data?.find((c: { status: string }) => c.status === 'open')
          if (!openCase) return 'SKIP — no "open" case to test'
          const { data } = await apiClient.patch(`/cases/${openCase.id}`, { status: 'closed' })
          if (data.data?.status !== 'closed') throw new Error('Status was not updated to "closed"')
          // Restore
          await apiClient.patch(`/cases/${openCase.id}`, { status: 'open' })
          return `OK — case "${openCase.name}" closed successfully (restored to open)`
        },
      },
      {
        id: 'CASE-04',
        name: 'Get Case Summary',
        what: 'GET /cases/:id/summary — case overview with agents, deployments, checklist runs',
        expected: 'Case object with nested arrays: agents, deployments, checklist_runs, jobs',
        async run() {
          const { data: listData } = await apiClient.get('/cases')
          if (!listData.data?.length) return 'SKIP — no case to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/cases/${id}/summary`)
          const s = data.data
          if (!s?.id) throw new Error('Missing id trong summary')
          const agentCount = s.agents?.length ?? 0
          const jobCount   = s.jobs?.length ?? 0
          return `OK — case "${s.name}" | ${agentCount} agent(s), ${jobCount} job(s)`
        },
      },
      {
        id: 'CASE-05',
        name: 'Case Does Not Exist → 404',
        what: 'GET /cases/:id/summary with a non-existent UUID',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/cases/00000000-0000-0000-0000-000000000000/summary')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'CASE-06',
        name: 'Case Unicode Name (Vietnamese)',
        what: 'POST /cases with a name containing Vietnamese UTF-8 characters',
        expected: 'Case created successfully, name stored with correct encoding',
        async run() {
          const name = `Sự cố APT ${Date.now()}`
          const { data } = await apiClient.post('/cases', { name, description: 'UTF-8 test' })
          if (!data.data?.id) throw new Error('Missing id in response')
          if (data.data.name !== name) throw new Error(`Name was altered: "${data.data.name}" ≠ "${name}"`)
          return `OK — Unicode case created successfully: "${data.data.name}"`
        },
      },
      {
        id: 'CASE-07',
        name: 'New Case Appears In List',
        what: 'POST /cases then GET /cases — confirm the new case is indexed immediately',
        expected: 'The newly created case must appear in GET /cases',
        async run() {
          const name = `__test_list_${Date.now()}`
          const { data: createData } = await apiClient.post('/cases', { name, description: 'list verify' })
          const newId = createData.data?.id
          if (!newId) throw new Error('No id after creation')
          const { data: listData } = await apiClient.get('/cases')
          const found = listData.data?.find((c: { id: string }) => c.id === newId)
          if (!found) throw new Error(`Case ${newId.slice(0,8)} did not appear in the list!`)
          return `OK — case "${name}" appears correctly in the list`
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
        name: 'Get Active ELK Config',
        what: 'GET /elk/config — get the active Elasticsearch configuration',
        expected: 'Config object with url, index pattern (key not leaked)',
        async run() {
          const { data } = await apiClient.get('/elk/config')
          if (!data.data) throw new Error('No config was returned')
          const cfg = data.data
          return `OK — ELK profile: "${cfg.name ?? 'default'}" | host: ${cfg.url ?? 'N/A'}`
        },
      },
      {
        id: 'ELK-02',
        name: 'List ELK Profiles',
        what: 'GET /elk/configs — get all ELK config profiles (multi-profile support)',
        expected: 'Array of configs, each item has id, name, url, is_active',
        async run() {
          const { data } = await apiClient.get('/elk/configs')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          const active = data.data.find((c: { is_active?: boolean }) => c.is_active)
          return `OK — ${data.data.length} ELK profile(s), active: "${active?.name ?? 'none'}"`
        },
      },
      {
        id: 'ELK-03',
        name: 'Parse IOC File (Classify IOCs)',
        what: 'POST /elk/iocs/parse — classify IOC lines by type: IPv4, hash, domain, URL…',
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
          if (!data.data) throw new Error('No data in response')
          const types = Object.entries(data.data as Record<string, unknown[]>)
            .filter(([, v]) => v.length > 0)
            .map(([k, v]) => `${k}:${v.length}`)
            .join(', ')
          return `OK — classified: ${types}`
        },
      },
      {
        id: 'ELK-04',
        name: 'List Saved Hunt Results',
        what: 'GET /elk/hunt/results — history of recorded IOC hunts',
        expected: 'Array of results with title, iocs_used, total_hits, status',
        async run() {
          const { data } = await apiClient.get('/elk/hunt/results')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} saved hunt result(s)`
        },
      },
      {
        id: 'ELK-05',
        name: 'Create & Delete ELK Profile',
        what: 'POST /elk/configs → activate → delete the test profile',
        expected: 'Profile created, can be activated, then deleted',
        async run() {
          const { data: createData } = await apiClient.post('/elk/configs', {
            name: `__test_elk_${Date.now()}`,
            url: 'http://localhost:9200',
            username: 'elastic',
            password: 'test',
            index_pattern: 'logs-*',
          })
          const cfg = createData.data
          if (!cfg?.id) throw new Error('Missing id in response')
          try {
            await apiClient.delete(`/elk/configs/${cfg.id}`)
          } catch {
            throw new Error(`Created OK but delete failed (id: ${cfg.id})`)
          }
          return `OK — ELK profile created & deleted successfully, credentials hidden`
        },
      },
      {
        id: 'ELK-06',
        name: 'Get Hunt Result Detail',
        what: 'GET /elk/hunt/results/:id — get a hunt result with hits and metadata',
        expected: 'Result object has title, iocs_used, total_hits, status',
        async run() {
          const { data: listData } = await apiClient.get('/elk/hunt/results')
          if (!listData.data?.length) return 'SKIP — no hunt result'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/elk/hunt/results/${id}`)
          const r = data.data
          if (!r?.id) throw new Error('Missing id in response')
          return `OK — result "${r.title ?? id.slice(0,8)}" | hits: ${r.total_hits ?? 0} | status: ${r.status}`
        },
      },
      {
        id: 'ELK-07',
        name: 'Hunt Result Does Not Exist → 404',
        what: 'GET /elk/hunt/results/:id with a non-existent UUID',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/elk/hunt/results/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
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
        name: 'List AI Providers',
        what: 'GET /ai/providers — get the list of configured AI providers',
        expected: 'Array of providers, API key not leaked (has_key instead)',
        async run() {
          const { data } = await apiClient.get('/ai/providers')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          const withKey = data.data.filter((p: { api_key?: string }) => p.api_key)
          if (withKey.length > 0) throw new Error('API key leaked in the response!')
          return `OK — ${data.data.length} AI provider(s), keys hidden`
        },
      },
      {
        id: 'AI-02',
        name: 'Create & Delete AI Provider (Lifecycle)',
        what: 'POST /ai/providers → verify the key is encrypted (has_key=true) → DELETE cleanup',
        expected: 'Provider created with has_key=true, api_key not leaked, deletable',
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
          if (!p?.id) throw new Error('Missing id in response')
          if (p?.api_key) throw new Error('API key leaked in the response!')
          if (!p?.has_key) throw new Error('has_key must be true after providing a key')
          try {
            await apiClient.delete(`/ai/providers/${p.id}`)
          } catch {
            throw new Error(`Created OK but delete failed (id: ${p.id.slice(0,8)})`)
          }
          return `OK — provider created (key encrypted, has_key=true), fully deleted`
        },
      },
      {
        id: 'AI-03',
        name: 'Test Provider Connection',
        what: 'POST /ai/providers/:id/test — check the real connection to the AI API',
        expected: 'Response has a success=true/false field with a clear message',
        async run() {
          const { data: listData } = await apiClient.get('/ai/providers')
          if (!listData.data?.length) return 'SKIP — no provider to test'
          const id = listData.data[0].id
          const { data } = await apiClient.post(`/ai/providers/${id}/test`)
          if (data.success === undefined) throw new Error('Missing success field in response')
          const result = data.success ? 'connection successful' : `failed: ${data.error ?? 'unknown'}`
          return `OK — provider "${listData.data[0].name}": ${result}`
        },
      },
      {
        id: 'AI-04',
        name: 'List Analysis Sessions',
        what: 'GET /ai/sessions — history of AI analysis runs',
        expected: 'Array of sessions with source_type, status, provider info',
        async run() {
          const { data } = await apiClient.get('/ai/sessions')
          if (!Array.isArray(data.data)) throw new Error('data.data is not an array')
          return `OK — ${data.data.length} analysis session(s) in history`
        },
      },
      {
        id: 'AI-05',
        name: 'Get Session Detail',
        what: 'GET /ai/sessions/:id — session with chain steps and result',
        expected: 'Session object has steps (JSON array), result (markdown report)',
        async run() {
          const { data: listData } = await apiClient.get('/ai/sessions')
          if (!listData.data?.length) return 'SKIP — no session to test'
          const id = listData.data[0].id
          const { data } = await apiClient.get(`/ai/sessions/${id}`)
          const s = data.data
          if (!s?.id) throw new Error('Missing id in response')
          const raw = s.steps
          const steps = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw).length : 0
          return `OK — session ${id.slice(0,8)} | status: ${s.status} | ${steps} steps | ${s.result?.length ?? 0} chars`
        },
      },
      {
        id: 'AI-06',
        name: 'Session Does Not Exist → 404',
        what: 'GET /ai/sessions/:id with a non-existent UUID',
        expected: 'HTTP 404 Not Found',
        async run() {
          try {
            await apiClient.get('/ai/sessions/00000000-0000-0000-0000-000000000000')
            throw new Error('Expected 404 but got 200')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 404) return 'OK — 404 Not Found (correct)'
            throw err
          }
        },
      },
      {
        id: 'AI-07',
        name: 'Invalid Provider Type → 400',
        what: 'POST /ai/providers with provider_type="unsupported_xyz"',
        expected: 'HTTP 400 — validation error',
        async run() {
          try {
            await apiClient.post('/ai/providers', {
              name: '__test_invalid_type',
              provider_type: 'unsupported_ai_xyz',
              api_key: 'test',
              model: 'test-model',
            })
            throw new Error('Server accepted an invalid provider_type!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 400) return 'OK — invalid provider_type rejected (400)'
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
        name: 'Health Check Returns 4 Services',
        what: 'GET /system/health — check PostgreSQL, Redis, Storage, WS Hub status',
        expected: 'Response has 4 fields: postgres, redis, storage, ws_hub',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const h = data.data
          if (!h) throw new Error('No data in response')
          const required = ['postgres', 'redis', 'storage', 'ws_hub']
          const missing = required.filter(k => !(k in h))
          if (missing.length > 0) throw new Error(`Missing fields: ${missing.join(', ')}`)
          const statuses = required.map(k => `${k}:${h[k]}`).join(' | ')
          return `OK — ${statuses}`
        },
      },
      {
        id: 'SYS-02',
        name: 'Server Resources In Health',
        what: 'GET /system/health — check the server CPU/RAM/Disk',
        expected: 'Response has a "server" field with cpu_percent, ram_used_mb, disk_used_gb',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const server = data.data?.server
          if (!server) return 'SKIP — server resources not implemented yet'
          if (server.cpu_percent === undefined) throw new Error('Missing cpu_percent')
          if (server.ram_used_mb === undefined) throw new Error('Missing ram_used_mb')
          if (server.disk_used_gb === undefined) throw new Error('Missing disk_used_gb')
          return `OK — CPU: ${server.cpu_percent.toFixed(1)}% | RAM: ${server.ram_used_mb}MB | Disk: ${server.disk_used_gb}GB`
        },
      },
      {
        id: 'SYS-03',
        name: 'Agent Resources Trong Health',
        what: 'GET /system/health — check for the resource-usage array of online agents',
        expected: 'Response has an "agent_resources" field that is an array (may be empty)',
        async run() {
          const { data } = await apiClient.get('/system/health')
          const resources = data.data?.agent_resources
          if (resources === undefined) return 'SKIP — agent_resources not implemented yet'
          if (!Array.isArray(resources)) throw new Error('agent_resources must be an array')
          return `OK — ${resources.length} agent(s) reporting resources`
        },
      },
      {
        id: 'SYS-04',
        name: 'Token Stats Endpoint',
        what: 'GET /system/token-stats — get AI token usage stats',
        expected: 'Object has by_provider (array) and total_tokens (number)',
        async run() {
          const { data } = await apiClient.get('/system/token-stats')
          if (!data.data) throw new Error('No data in response')
          const stats = data.data
          if (!Array.isArray(stats.by_provider)) throw new Error('by_provider must be an array')
          const total = stats.total_tokens ?? 0
          return `OK — total ${total.toLocaleString()} token(s) | ${stats.by_provider.length} provider(s)`
        },
      },
      {
        id: 'SYS-05',
        name: 'Health Endpoint Requires Auth',
        what: 'GET /system/health without a JWT — protect infrastructure info',
        expected: 'HTTP 401 — server info not exposed to unauthenticated users',
        async run() {
          try {
            await rawAxios.get('/system/health')
            throw new Error('System info exposed to an unauthenticated request!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — health endpoint is protected (401)'
            throw err
          }
        },
      },
    ],
  },

  // ─── 11. Egress Proxy ─────────────────────────────────────────────────────
  {
    id: 'proxy',
    label: 'Egress Proxy',
    icon: Shield,
    color: 'text-indigo-400',
    borderColor: 'border-indigo-500/30',
    bgColor: 'bg-indigo-500/5',
    tests: [
      {
        id: 'PROXY-01',
        name: 'Proxy Status Endpoint Returns All Fields',
        what: 'GET /system/proxy — report the applied egress proxy config (read from runtime env)',
        expected: 'Object has outbound_configured, outbound_proxy, no_proxy, tor_configured, tor_proxy, darkweb_sources',
        async run() {
          const { data } = await apiClient.get('/system/proxy')
          const p = data.data
          if (!p) throw new Error('No data in response')
          for (const k of ['outbound_configured', 'tor_configured']) {
            if (typeof p[k] !== 'boolean') throw new Error(`Field ${k} must be a boolean`)
          }
          for (const k of ['outbound_proxy', 'no_proxy', 'tor_proxy']) {
            if (typeof p[k] !== 'string') throw new Error(`Field ${k} must be a string`)
          }
          if (typeof p.darkweb_sources !== 'number') throw new Error('darkweb_sources must be a number')
          return `OK — outbound: ${p.outbound_configured ? p.outbound_proxy : 'OFF'} | tor: ${p.tor_configured ? 'ON' : 'OFF'} | darkweb sources: ${p.darkweb_sources}`
        },
      },
      {
        id: 'PROXY-02',
        name: 'Mask Credentials Trong Proxy URL',
        what: 'POST /system/proxy/validate with a user:pass proxy — server must fully mask credentials',
        expected: 'masked_proxy = scheme://host:port, no "@"/user/pass left, leaked=false',
        async run() {
          const { data } = await apiClient.post('/system/proxy/validate', {
            proxy_url: 'http://admin:S3cretP@ss@10.0.0.5:8080',
          })
          const d = data.data
          if (!d) throw new Error('No data in response')
          if (d.leaked) throw new Error('Server reported leaked=true — credentials were not masked')
          if (String(d.masked_proxy).includes('@'))
            throw new Error(`masked_proxy still has "@": ${d.masked_proxy}`)
          if (String(d.masked_proxy).toLowerCase().includes('admin') || String(d.masked_proxy).includes('S3cret'))
            throw new Error(`masked_proxy leaked credentials: ${d.masked_proxy}`)
          if (!String(d.masked_proxy).includes('10.0.0.5:8080'))
            throw new Error(`masked_proxy lost host:port: ${d.masked_proxy}`)
          return `OK — masked: http://admin:S3cret…@10.0.0.5:8080 → ${d.masked_proxy}`
        },
      },
      {
        id: 'PROXY-03',
        name: 'NO_PROXY Always Bypasses Loopback',
        what: 'POST /system/proxy/validate — effective NO_PROXY must always include localhost/127.0.0.1/::1 + operator exceptions',
        expected: 'effective_no_proxy contains localhost, 127.0.0.1, ::1 and "10.20.30.0/24"',
        async run() {
          const { data } = await apiClient.post('/system/proxy/validate', {
            no_proxy: '10.20.30.0/24',
          })
          const np = String(data.data?.effective_no_proxy ?? '')
          for (const must of ['localhost', '127.0.0.1', '::1', '10.20.30.0/24']) {
            if (!np.includes(must))
              throw new Error(`effective_no_proxy missing "${must}": ${np}`)
          }
          return `OK — NO_PROXY always bypasses loopback + exceptions: ${np}`
        },
      },
      {
        id: 'PROXY-04',
        name: 'Configured Flag Matches Proxy Value',
        what: 'GET /system/proxy — outbound_configured is true iff outbound_proxy has a value; same for tor',
        expected: 'Boolean flags consistent with their proxy strings',
        async run() {
          const { data } = await apiClient.get('/system/proxy')
          const p = data.data
          if (p.outbound_configured !== (String(p.outbound_proxy).length > 0))
            throw new Error('outbound_configured does not match outbound_proxy')
          if (p.tor_configured !== (String(p.tor_proxy).length > 0))
            throw new Error('tor_configured does not match tor_proxy')
          return 'OK — configured flags consistent with proxy values'
        },
      },
      {
        id: 'PROXY-05',
        name: 'Proxy Status Requires Auth',
        what: 'GET /system/proxy without a JWT — do not expose infra config to unauthenticated',
        expected: 'HTTP 401 Unauthorized',
        async run() {
          try {
            await rawAxios.get('/system/proxy')
            throw new Error('Proxy config exposed to an unauthenticated request!')
          } catch (err: unknown) {
            const e = err as { response?: { status: number } }
            if (e.response?.status === 401) return 'OK — proxy status endpoint is protected (401)'
            throw err
          }
        },
      },
      {
        id: 'PROXY-06',
        name: 'Proxy Status Includes Live Health',
        what: 'GET /system/proxy — the live status carries a health snapshot (healthy/last_check/latency)',
        expected: 'data.health exists with a boolean "healthy" and numeric "latency_ms"',
        async run() {
          const { data } = await apiClient.get('/system/proxy')
          const hh = data.data?.health
          if (!hh) throw new Error('No health object in proxy status')
          if (typeof hh.healthy !== 'boolean') throw new Error('health.healthy must be boolean')
          if (typeof hh.latency_ms !== 'number') throw new Error('health.latency_ms must be number')
          if (typeof data.data?.fallback_direct !== 'boolean') throw new Error('fallback_direct must be boolean')
          return `OK — healthy: ${hh.healthy} | latency: ${hh.latency_ms}ms | fallback-direct: ${data.data.fallback_direct}`
        },
      },
      {
        id: 'PROXY-07',
        name: 'On-demand Proxy Health Probe',
        what: 'POST /system/proxy/check — run the health probe immediately and return a fresh snapshot',
        expected: 'Returns status with a health.last_check timestamp',
        async run() {
          const { data } = await apiClient.post('/system/proxy/check')
          const lc = data.data?.health?.last_check
          if (!lc) throw new Error('No health.last_check after probe')
          return `OK — probed at ${lc} (healthy: ${data.data.health.healthy})`
        },
      },
    ],
  },

  // ─── 12. OOB / Catch (Interaction Server) ─────────────────────────────────
  {
    id: 'oob',
    label: 'Catch (OOB)',
    icon: Crosshair,
    color: 'text-rose-400',
    borderColor: 'border-rose-500/30',
    bgColor: 'bg-rose-500/5',
    tests: [
      {
        id: 'OOB-01',
        name: 'Webhook Mode Always Ready',
        what: 'GET /osint/oob/config — webhook receiver runs on this backend with no extra setup',
        expected: 'webhook_ready=true and webhook_base ends with /oob/r/',
        async run() {
          const { data } = await apiClient.get('/osint/oob/config')
          const d = data.data
          if (!d?.webhook_ready) throw new Error('webhook_ready is not true')
          if (!String(d.webhook_base).endsWith('/oob/r/')) throw new Error(`unexpected webhook_base: ${d.webhook_base}`)
          return `OK — webhook ready | base: ${d.webhook_base} | OAST domain: ${d.domain || '(unset)'}`
        },
      },
      {
        id: 'OOB-02',
        name: 'Session Lifecycle (register → delete)',
        what: 'POST /osint/oob/register then DELETE the session',
        expected: 'register returns correlation_id + secret + payload.webhook; delete returns 200',
        async run() {
          const { data } = await apiClient.post('/osint/oob/register', { name: 'testcase-lifecycle' })
          const c = data.data?.client
          if (!c?.id || !c?.correlation_id) throw new Error('register missing client id/correlation_id')
          if (!c?.secret) throw new Error('register did not return a secret')
          if (!data.data?.payload?.webhook) throw new Error('register did not return a webhook payload')
          await apiClient.delete(`/osint/oob/clients/${c.id}`)
          return `OK — created+deleted session ${c.correlation_id}`
        },
      },
      {
        id: 'OOB-03',
        name: 'Smart Decoder Peels Multiple Layers',
        what: 'POST /osint/oob/decode with url(base64("id=42&role=admin"))',
        expected: 'layers ≥ 2 and final = "id=42&role=admin"',
        async run() {
          const inner = btoa('id=42&role=admin')
          const enc = encodeURIComponent(inner)
          const { data } = await apiClient.post('/osint/oob/decode', { input: enc })
          const d = data.data
          if (!d) throw new Error('no decode result')
          if (d.layers < 2) throw new Error(`expected ≥2 layers, got ${d.layers}`)
          if (d.final !== 'id=42&role=admin') throw new Error(`final = "${d.final}"`)
          return `OK — peeled ${d.layers} layers → ${d.final}`
        },
      },
      {
        id: 'OOB-04',
        name: 'Webhook Capture End-to-End',
        what: 'Register → fire an HTTP callback to the webhook URL → poll interactions',
        expected: 'The fired GET is captured and listed for the session',
        async run() {
          const { data } = await apiClient.post('/osint/oob/register', { name: 'testcase-capture' })
          const c = data.data.client
          const webhook: string = data.data.payload.webhook
          try {
            await fetch(`${webhook}/tc-probe?x=1`, { method: 'GET' })
            await new Promise(r => setTimeout(r, 1200))
            const res = await apiClient.get(`/osint/oob/clients/${c.id}/interactions`)
            const hits = res.data.data as Array<{ method?: string; path?: string }>
            if (!hits.length) throw new Error('callback was not captured')
            const hit = hits.find(h => (h.path ?? '').includes('tc-probe'))
            if (!hit) throw new Error('captured interactions do not include the probe path')
            return `OK — captured ${hits.length} interaction(s): ${hit.method} ${hit.path}`
          } finally {
            await apiClient.delete(`/osint/oob/clients/${c.id}`).catch(() => {})
          }
        },
      },
      {
        id: 'OOB-05',
        name: 'Conditional Response Rule Matches',
        what: 'Add a rule (POST → 418) → fire GET (default 200) and POST (rule 418)',
        expected: 'GET returns 200, POST returns 418 with the rule body',
        async run() {
          const { data } = await apiClient.post('/osint/oob/register', { name: 'testcase-rule' })
          const c = data.data.client
          const webhook: string = data.data.payload.webhook
          try {
            await apiClient.post(`/osint/oob/clients/${c.id}/rules`, {
              match_method: 'POST', status: 418, content_type: 'text/plain', body: 'teapot', priority: 0,
            })
            const g = await fetch(`${webhook}/r`, { method: 'GET' })
            const pst = await fetch(`${webhook}/r`, { method: 'POST', body: 'a=1' })
            if (g.status !== 200) throw new Error(`GET expected 200, got ${g.status}`)
            if (pst.status !== 418) throw new Error(`POST expected 418, got ${pst.status}`)
            return `OK — GET→200, POST→418 (rule matched)`
          } finally {
            await apiClient.delete(`/osint/oob/clients/${c.id}`).catch(() => {})
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
            <span className="text-gray-700">Expected: </span>{def.expected}
          </p>

          {/* Detail / Error */}
          {hasDetail && (
            <button
              onClick={() => setExpanded(e => !e)}
              className="flex items-center gap-1 mt-1.5 text-[11px] text-gray-500 hover:text-gray-300 transition-colors"
            >
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              {expanded ? 'Hide details' : 'View details'}
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
            Test the entire ForensicHub-v2 backend API — run tests individually or all at once to confirm the system works correctly.
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
            ? <><Loader2 className="h-4 w-4 animate-spin" /> Running…</>
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
          Overview of all categories
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
