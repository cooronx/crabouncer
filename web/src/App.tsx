import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, clearSession, login } from "./api";
import type { Actor, Application, Organization, Release, ServiceAccount, User, Workspace } from "./types";

type Tab = "users" | "applications" | "policy" | "decisions" | "audit";

function useAsyncError() {
  const [error, setError] = useState("");
  const run = useCallback(async <T,>(task: () => Promise<T>): Promise<T | undefined> => {
    setError("");
    try { return await task(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unknown error"); }
  }, []);
  return { error, setError, run };
}

export function App() {
  const path = window.location.pathname;
  if (path === "/login") return <LoginPage />;
  if (path.startsWith("/activate/")) return <ActivationPage token={path.slice("/activate/".length)} />;
  return <Dashboard />;
}

function LoginPage() {
  const { error, run } = useAsyncError();
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true);
    const data = new FormData(event.currentTarget);
    const result = await run(async () => { await login(String(data.get("email")), String(data.get("password"))); return true; });
    setBusy(false);
    if (result) {
      const target = new URLSearchParams(location.search).get("return_to") ?? "/";
      location.assign(target);
    }
  }
  return <AuthShell title="登录 Crabouncer" subtitle="统一身份与细粒度授权">
    <form onSubmit={submit} className="stack">
      <label>邮箱<input name="email" type="email" autoComplete="username" required autoFocus /></label>
      <label>密码<input name="password" type="password" autoComplete="current-password" minLength={12} required /></label>
      {error && <p className="error">{error}</p>}
      <button disabled={busy}>{busy ? "正在登录…" : "登录"}</button>
    </form>
  </AuthShell>;
}

function ActivationPage({ token }: { token: string }) {
  const { error, run } = useAsyncError(); const [done, setDone] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    const password = String(data.get("password"));
    if (password !== String(data.get("confirm"))) return;
    const result = await run(async () => { await api<void>(`/api/v1/activations/${encodeURIComponent(token)}`, { method: "POST", body: JSON.stringify({ password }) }); return true; });
    if (result) setDone(true);
  }
  return <AuthShell title="激活账户" subtitle="设置一个至少 12 个字符的密码">
    {done ? <div className="stack"><p className="success">账户已激活。</p><a className="button" href="/login">前往登录</a></div> :
      <form onSubmit={submit} className="stack"><label>新密码<input name="password" type="password" minLength={12} required /></label><label>确认密码<input name="confirm" type="password" minLength={12} required /></label>{error && <p className="error">{error}</p>}<button>激活</button></form>}
  </AuthShell>;
}

function AuthShell({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return <main className="auth-page"><section className="auth-card"><div className="brand-mark">C</div><h1>{title}</h1><p className="muted">{subtitle}</p>{children}</section></main>;
}

function Dashboard() {
  const { error, run } = useAsyncError();
  const [actor, setActor] = useState<Actor>(); const [organizations, setOrganizations] = useState<Organization[]>([]); const [organizationId, setOrganizationId] = useState(""); const [tab, setTab] = useState<Tab>("applications"); const [selectedApp, setSelectedApp] = useState<Application>();
  const refresh = useCallback(async () => {
    const me = await run(() => api<Actor>("/api/v1/session/me"));
    if (!me) { location.assign("/login"); return; }
    setActor(me); const orgs = await run(() => api<Organization[]>("/api/v1/organizations")); if (orgs) { setOrganizations(orgs); setOrganizationId((current) => current || me.organization_id || orgs[0]?.id); }
  }, [run]);
  useEffect(() => { void refresh(); }, [refresh]);
  async function signOut() { await run(() => api<void>("/api/v1/session", { method: "DELETE" })); clearSession(); location.assign("/login"); }
  if (!actor) return <main className="loading">正在加载 Crabouncer…</main>;
  return <div className="shell">
    <aside><div className="brand"><span className="brand-mark small">C</span><div><strong>Crabouncer</strong><small>IAM & PDP</small></div></div>
      <label className="org-picker">组织<select value={organizationId} onChange={(event) => { setOrganizationId(event.target.value); setSelectedApp(undefined); }}>{organizations.map((org) => <option value={org.id} key={org.id}>{org.display_name}</option>)}</select></label>
      <nav>{(["users", "applications", "policy", "decisions", "audit"] as Tab[]).map((item) => <button className={tab === item ? "active" : "ghost"} onClick={() => setTab(item)} key={item}>{({ users: "用户", applications: "应用", policy: "策略", decisions: "决策日志", audit: "审计日志" })[item]}</button>)}</nav>
      <div className="account"><strong>{actor.display_name}</strong><small>{actor.is_system_admin ? "系统管理员" : actor.role}</small><button className="link" onClick={signOut}>退出</button></div>
    </aside>
    <main className="workspace"><header><div><h1>{organizations.find((o) => o.id === organizationId)?.display_name}</h1><p className="muted">身份与授权控制台</p></div>{actor.is_system_admin && <CreateOrganization onCreated={refresh} />}</header>{error && <p className="error banner">{error}</p>}
      {tab === "users" && <Users organizationId={organizationId} />}
      {tab === "applications" && <Applications organizationId={organizationId} onSelect={(app) => { setSelectedApp(app); setTab("policy"); }} />}
      {tab === "policy" && <PolicyStudio organizationId={organizationId} initial={selectedApp} />}
      {tab === "decisions" && <Logs organizationId={organizationId} kind="decision" />}
      {tab === "audit" && <Logs organizationId={organizationId} kind="audit" />}
    </main>
  </div>;
}

function CreateOrganization({ onCreated }: { onCreated: () => Promise<void> }) {
  const [open, setOpen] = useState(false); const [activation, setActivation] = useState(""); const { error, run } = useAsyncError();
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget)); const result = await run(() => api<{ activation_url: string }>("/api/v1/organizations", { method: "POST", body: JSON.stringify(data) })); if (result) { setActivation(result.activation_url); await onCreated(); } }
  return <>{<button onClick={() => { setActivation(""); setOpen(true); }}>新建组织</button>}{open && <Dialog title="新建组织" close={() => setOpen(false)}>{activation ? <div className="stack"><CopyNotice label="首位 Owner 激活链接（仅显示一次）" value={activation} /><button onClick={() => setOpen(false)}>完成</button></div> : <form onSubmit={submit} className="stack"><label>标识<input name="name" required pattern="[a-z0-9-]+" /></label><label>显示名称<input name="display_name" required /></label><label>首位 Owner 邮箱<input name="owner_email" type="email" required /></label><label>Owner 名称<input name="owner_display_name" required /></label>{error && <p className="error">{error}</p>}<button>创建并生成激活链接</button></form>}</Dialog>}</>;
}

function Users({ organizationId }: { organizationId: string }) {
  const { error, run } = useAsyncError(); const [users, setUsers] = useState<User[]>([]); const [activation, setActivation] = useState("");
  const refresh = useCallback(async () => { const rows = await run(() => api<User[]>(`/api/v1/organizations/${organizationId}/users`)); if (rows) setUsers(rows); }, [organizationId, run]); useEffect(() => { void refresh(); }, [refresh]);
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const result = await run(() => api<{ activation_url: string }>(`/api/v1/organizations/${organizationId}/users`, { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) })); if (result) { setActivation(result.activation_url); event.currentTarget.reset(); await refresh(); } }
  return <Section title="用户" aside={<form onSubmit={submit} className="inline-form"><input name="email" type="email" placeholder="邮箱" required /><input name="display_name" placeholder="名称" required /><select name="role"><option>member</option><option>admin</option><option>owner</option></select><button>添加</button></form>}>
    {activation && <CopyNotice label="激活链接（仅显示一次）" value={activation} />}{error && <p className="error">{error}</p>}<Table headers={["用户", "角色", "状态"]}>{users.map((user) => <tr key={user.id}><td><strong>{user.display_name}</strong><small>{user.email}</small></td><td>{user.role}</td><td><Status value={user.status} /></td></tr>)}</Table>
  </Section>;
}

function Applications({ organizationId, onSelect }: { organizationId: string; onSelect: (app: Application) => void }) {
  const { error, run } = useAsyncError(); const [apps, setApps] = useState<Application[]>([]);
  const refresh = useCallback(async () => { const rows = await run(() => api<Application[]>(`/api/v1/organizations/${organizationId}/applications`)); if (rows) setApps(rows); }, [organizationId, run]); useEffect(() => { void refresh(); }, [refresh]);
  async function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); await run(() => api(`/api/v1/organizations/${organizationId}/applications`, { method: "POST", body: JSON.stringify({ name: data.get("name"), redirect_uris: String(data.get("redirect_uri")).split(/\s+/).filter(Boolean), allowed_scopes: ["openid", "profile", "email", "offline_access"] }) })); event.currentTarget.reset(); await refresh(); }
  return <Section title="Applications" aside={<form className="inline-form" onSubmit={submit}><input name="name" placeholder="应用名称" required /><input name="redirect_uri" type="url" placeholder="https://app/callback" required /><button>创建</button></form>}>{error && <p className="error">{error}</p>}<div className="card-grid">{apps.map((app) => <article className="card" key={app.id}><div><Status value={app.enabled ? "active" : "disabled"} /><h3>{app.name}</h3><code>{app.client_id}</code></div><button className="secondary" onClick={() => onSelect(app)}>管理策略</button></article>)}</div></Section>;
}

function PolicyStudio({ organizationId, initial }: { organizationId: string; initial?: Application }) {
  const { error, setError, run } = useAsyncError(); const [apps, setApps] = useState<Application[]>([]); const [appId, setAppId] = useState(initial?.id ?? ""); const [workspace, setWorkspace] = useState<Workspace>(); const [accounts, setAccounts] = useState<ServiceAccount[]>([]); const [releases, setReleases] = useState<Release[]>([]); const [secret, setSecret] = useState(""); const [simulation, setSimulation] = useState("");
  useEffect(() => { void run(() => api<Application[]>(`/api/v1/organizations/${organizationId}/applications`)).then((rows) => { if (rows) { setApps(rows); setAppId((id) => id || rows[0]?.id || ""); } }); }, [organizationId, run]);
  const load = useCallback(async () => { if (!appId) return; const [space, serviceAccounts, releaseRows] = await Promise.all([run(() => api<Workspace>(`/api/v1/applications/${appId}/workspace`)), run(() => api<ServiceAccount[]>(`/api/v1/applications/${appId}/service-accounts`)), run(() => api<Release[]>(`/api/v1/applications/${appId}/releases`))]); if (space) setWorkspace(space); if (serviceAccounts) setAccounts(serviceAccounts); if (releaseRows) setReleases(releaseRows); }, [appId, run]); useEffect(() => { void load(); }, [load]);
  function updateJson(field: "policies" | "entities", value: string) { try { const parsed = JSON.parse(value) as unknown[]; setWorkspace((current) => current ? { ...current, [field]: parsed } : current); setError(""); } catch { setError(`${field} 不是有效 JSON`); } }
  async function save() { if (!workspace) return false; return Boolean(await run(async () => { await api<void>(`/api/v1/applications/${appId}/workspace`, { method: "PUT", body: JSON.stringify(workspace) }); return true; })); }
  async function publish() { if (!await save()) return; await run(() => api(`/api/v1/applications/${appId}/releases`, { method: "POST" })); await load(); }
  async function simulate(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const source = String(new FormData(event.currentTarget).get("request")); const result = await run(async () => { const request: unknown = JSON.parse(source); return api<Record<string, unknown>>(`/api/v1/applications/${appId}/workspace/simulate`, { method: "POST", body: JSON.stringify(request) }); }); if (result) setSimulation(JSON.stringify(result, null, 2)); }
  async function createAccount(event: FormEvent<HTMLFormElement>) { event.preventDefault(); const data = new FormData(event.currentTarget); const result = await run(() => api<{ client_id: string; client_secret: string }>(`/api/v1/applications/${appId}/service-accounts`, { method: "POST", body: JSON.stringify({ name: data.get("name"), scopes: ["authzen:evaluate"] }) })); if (result) { setSecret(`${result.client_id}:${result.client_secret}`); await load(); } }
  return <Section title="Policy Studio" aside={<select value={appId} onChange={(e) => setAppId(e.target.value)}>{apps.map((app) => <option value={app.id} key={app.id}>{app.name}</option>)}</select>}>
    {!appId ? <Empty text="请先创建 Application" /> : <>{error && <p className="error">{error}</p>}<div className="split"><div className="stack panel"><h3>策略工作区</h3><label>Cedar Schema<textarea rows={12} value={workspace?.schema_source ?? ""} onChange={(e) => setWorkspace((w) => w ? { ...w, schema_source: e.target.value } : w)} spellCheck={false} /></label><label>Policies JSON<textarea rows={12} defaultValue={JSON.stringify(workspace?.policies ?? [], null, 2)} key={`${appId}-policies-${workspace?.application_id}`} onBlur={(e) => updateJson("policies", e.target.value)} spellCheck={false} /></label><label>Entities JSON<textarea rows={8} defaultValue={JSON.stringify(workspace?.entities ?? [], null, 2)} key={`${appId}-entities-${workspace?.application_id}`} onBlur={(e) => updateJson("entities", e.target.value)} spellCheck={false} /></label><div className="actions"><button className="secondary" onClick={save}>保存草稿</button><button onClick={publish}>验证并发布</button></div><form onSubmit={simulate} className="stack"><h3>策略模拟</h3><label>AuthZEN Request<textarea name="request" rows={10} defaultValue={JSON.stringify({ subject: { type: "User", id: "user-uuid", properties: {} }, action: { name: "document.read" }, resource: { type: "Document", id: "document-1", properties: { organization_id: organizationId } }, context: {} }, null, 2)} /></label><button className="secondary">运行模拟</button>{simulation && <pre>{simulation}</pre>}</form></div>
      <div className="stack"><div className="panel"><h3>Service Accounts</h3><form onSubmit={createAccount} className="inline-form"><input name="name" placeholder="名称" required /><button>创建</button></form>{secret && <CopyNotice label="Client ID : Secret（仅显示一次）" value={secret} />}{accounts.map((account) => <div className="list-row" key={account.id}><div><strong>{account.name}</strong><code>{account.client_id}</code></div><div className="actions"><Status value={account.enabled ? "active" : "disabled"} /><button className="secondary" onClick={async () => { const result = await run(() => api<{ client_secret: string }>(`/api/v1/service-accounts/${account.id}/secrets`, { method: "POST" })); if (result) setSecret(`${account.client_id}:${result.client_secret}`); }}>轮换密钥</button></div></div>)}</div><div className="panel"><h3>Releases</h3>{releases.map((release) => <div className="list-row" key={release.id}><div><strong>v{release.version}</strong><small>{new Date(release.created_at).toLocaleString()}</small></div>{release.active ? <Status value="active" /> : <button className="secondary" onClick={async () => { await run(() => api(`/api/v1/applications/${appId}/releases/${release.id}/activate`, { method: "POST" })); await load(); }}>回滚到此版本</button>}</div>)}</div></div></div></>}
  </Section>;
}

function Logs({ organizationId, kind }: { organizationId: string; kind: "decision" | "audit" }) { const { error, run } = useAsyncError(); const [rows, setRows] = useState<Record<string, unknown>[]>([]); useEffect(() => { void run(() => api<Record<string, unknown>[]>(`/api/v1/organizations/${organizationId}/${kind === "decision" ? "decision-logs" : "audit-logs"}`)).then((data) => data && setRows(data)); }, [organizationId, kind, run]); return <Section title={kind === "decision" ? "授权决策日志" : "管理审计日志"}>{error && <p className="error">{error}</p>}{rows.length ? <div className="log-list">{rows.map((row, index) => <details key={String(row.id ?? index)}><summary><Status value={row.decision === false ? "denied" : "active"} /> <strong>{String(row.action ?? row.reason ?? "decision")}</strong><small>{new Date(String(row.created_at)).toLocaleString()}</small></summary><pre>{JSON.stringify(row, null, 2)}</pre></details>)}</div> : <Empty text="暂无日志" />}</Section>; }

function Section({ title, aside, children }: { title: string; aside?: React.ReactNode; children: React.ReactNode }) { return <section><div className="section-title"><h2>{title}</h2>{aside}</div>{children}</section>; }
function Table({ headers, children }: { headers: string[]; children: React.ReactNode }) { return <div className="table-wrap"><table><thead><tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{children}</tbody></table></div>; }
function Status({ value }: { value: string }) { return <span className={`status ${value}`}>{value}</span>; }
function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }
function CopyNotice({ label, value }: { label: string; value: string }) { return <div className="copy"><small>{label}</small><code>{value}</code><button className="secondary" onClick={() => navigator.clipboard.writeText(value)}>复制</button></div>; }
function Dialog({ title, close, children }: { title: string; close: () => void; children: React.ReactNode }) { return <div className="overlay" role="dialog"><div className="dialog"><div className="section-title"><h2>{title}</h2><button className="ghost" onClick={close}>×</button></div>{children}</div></div>; }
