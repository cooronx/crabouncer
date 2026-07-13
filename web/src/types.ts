export interface Actor {
  id: string;
  organization_id: string;
  email: string;
  display_name: string;
  role: "owner" | "admin" | "member";
  is_system_admin: boolean;
}

export interface Organization {
  id: string;
  name: string;
  display_name: string;
  status: "active" | "disabled";
}

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: string;
  status: string;
}

export interface Application {
  id: string;
  organization_id: string;
  name: string;
  client_id: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  enabled: boolean;
}

export interface ServiceAccount {
  id: string;
  name: string;
  client_id: string;
  scopes: string[];
  enabled: boolean;
}

export interface Workspace {
  application_id: string;
  schema_source: string;
  policies: unknown[];
  entities: unknown[];
}

export interface Release {
  id: string;
  version: number;
  created_at: string;
  active: boolean;
}
