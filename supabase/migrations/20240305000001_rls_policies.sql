-- Enable RLS on all tables
ALTER TABLE base.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE base.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE base.workspace_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE base.workspace_user_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE base.settings ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for workspaces
CREATE POLICY "workspace isolation policy"
ON base.workspaces
as RESTRICTIVE
to authenticated
USING (id = (((SELECT auth.jwt()) -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

CREATE POLICY "select for workspaces"
ON base.workspaces
as PERMISSIVE
for SELECT
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['workspaces.read'::text]) AS user_has_permissions)
);

CREATE POLICY "update for workspaces"
ON base.workspaces
as PERMISSIVE
for UPDATE
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['workspaces.update'::text]) AS user_has_permissions)
);

CREATE POLICY "insert for workspaces"
ON base.workspaces
as PERMISSIVE
for INSERT
to service_role
WITH CHECK (
  true
);

-- Create RLS policies for users
CREATE POLICY "select for users"
ON base.users
as PERMISSIVE
for SELECT
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['users.read'::text]) AS user_has_permissions)
);

CREATE POLICY "update for users"
ON base.users
as PERMISSIVE
for UPDATE
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['users.update'::text]) AS user_has_permissions) OR (id = (SELECT auth.uid() AS uid))
);

-- Create RLS policies for workspace_users
CREATE POLICY "workspace isolation policy for workspace_users"
ON base.workspace_users
as RESTRICTIVE
to authenticated
USING (workspace_id = (((SELECT auth.jwt()) -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

CREATE POLICY "select for only workspace users"
ON base.workspace_users
as PERMISSIVE
for SELECT
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['users.read'::text]) AS user_has_permissions)
);

CREATE POLICY "insert for workspace users"
ON base.workspace_users
as PERMISSIVE
for INSERT
to authenticated
with check (
  (SELECT base.user_has_permissions(ARRAY['users.create'::text]) AS user_has_permissions)
);

CREATE POLICY "update for workspace users or self"
ON base.workspace_users
as PERMISSIVE
for UPDATE
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['users.update'::text]) AS user_has_permissions) OR (user_id = (SELECT auth.uid() AS uid))
);

CREATE POLICY "delete for workspace users or self"
ON base.workspace_users
as PERMISSIVE
for DELETE
to authenticated
using (
  (SELECT base.user_has_permissions(ARRAY['users.delete'::text]) AS user_has_permissions) OR (user_id = (SELECT auth.uid() AS uid))
);

-- Create RLS policies for workspace_user_permissions
CREATE POLICY "select for workspace user permissions to supabase_auth_admin"
ON base.workspace_user_permissions
as PERMISSIVE
for SELECT
to supabase_auth_admin
using (
  true
);

-- Create RLS policies for settings table
CREATE POLICY "workspace isolation policy for settings"
ON base.settings
AS RESTRICTIVE
TO authenticated
USING (workspace_id = (((SELECT auth.jwt()) -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid);

CREATE POLICY "select policy for settings"
ON base.settings
AS PERMISSIVE
FOR SELECT
TO authenticated
USING (
    (SELECT base.user_has_permissions(ARRAY['settings.read'::text]) AS user_has_permissions)
    OR (created_by_id = (SELECT auth.uid() AS uid))
);

CREATE POLICY "insert policy for settings"
ON base.settings
AS PERMISSIVE
FOR INSERT
TO authenticated
WITH CHECK (
    (SELECT base.user_has_permissions(ARRAY['settings.create'::text]) AS user_has_permissions)
);

CREATE POLICY "update policy for settings"
ON base.settings
AS PERMISSIVE
FOR UPDATE
TO authenticated
USING (
    (SELECT base.user_has_permissions(ARRAY['settings.update'::text]) AS user_has_permissions)
    OR (created_by_id = (SELECT auth.uid() AS uid))
);

CREATE POLICY "delete policy for settings"
ON base.settings
AS PERMISSIVE
FOR DELETE
TO authenticated
USING (
    (SELECT base.user_has_permissions(ARRAY['settings.delete'::text]) AS user_has_permissions)
    OR (created_by_id = (SELECT auth.uid() AS uid))
); 