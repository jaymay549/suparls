-- Create the base schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS base;

-- Grant permissions on the base schema
GRANT USAGE ON SCHEMA "base" TO "postgres";
GRANT USAGE ON SCHEMA "base" TO "authenticated";
GRANT USAGE ON SCHEMA "base" TO "service_role";

-- Set default privileges for the base schema
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON SEQUENCES TO "service_role";

ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON FUNCTIONS TO "service_role";

ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "base" GRANT ALL ON TABLES TO "service_role";

-- Create the user_has_permissions function
CREATE OR REPLACE FUNCTION base.user_has_permissions(requested_permissions TEXT[])
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER STABLE
AS $$
DECLARE
    user_permissions JSONB;
BEGIN
    -- Get user permissions from JWT
    user_permissions := (auth.jwt() ->> 'user_permissions')::jsonb;
    
    -- Return false if user_permissions is null
    IF user_permissions IS NULL THEN
        RETURN false;
    END IF;

    -- Check if any requested permission exists in user permissions
    RETURN EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(user_permissions) AS user_permission
        WHERE user_permission = ANY(requested_permissions)
    );
END;
$$;

-- Create a function to get user permissions and add them to the JWT token
CREATE OR REPLACE FUNCTION auth.jwt_custom_claims()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
    user_id uuid;
    workspace_id uuid;
    user_permissions text[];
    result jsonb;
BEGIN
    -- Get the user ID from the request
    user_id := auth.uid();
    
    -- If user_id is null, return empty object
    IF user_id IS NULL THEN
        RETURN '{}'::jsonb;
    END IF;
    
    -- Get the workspace_id from the user's app_metadata
    workspace_id := ((auth.jwt() -> 'app_metadata')::jsonb ->> 'workspace_id')::uuid;
    
    -- If workspace_id is null, return empty object
    IF workspace_id IS NULL THEN
        RETURN '{}'::jsonb;
    END IF;
    
    -- Get the user's permissions for the workspace
    SELECT permissions INTO user_permissions
    FROM base.workspace_user_permissions
    WHERE user_id = auth.uid() AND workspace_id = workspace_id;
    
    -- Create the result JSON with user permissions
    IF user_permissions IS NOT NULL THEN
        result := jsonb_build_object('user_permissions', to_jsonb(user_permissions));
    ELSE
        result := jsonb_build_object('user_permissions', '[]'::jsonb);
    END IF;
    
    RETURN result;
END;
$$;

-- Create workspaces table
CREATE TABLE base.workspaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  slug VARCHAR(255) NOT NULL UNIQUE,
  extra_data JSONB,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);

COMMENT ON COLUMN base.workspaces.extra_data IS 'Add extra details for workspaces';

CREATE UNIQUE INDEX idx_workspaces_slug ON base.workspaces (slug);

ALTER TABLE base.workspaces ENABLE ROW LEVEL SECURITY;
GRANT ALL ON base.workspaces to authenticated;
GRANT INSERT ON base.workspaces TO service_role;

-- Create users table
CREATE TABLE base.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL UNIQUE,
  extra_data JSONB,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now()
);

COMMENT ON COLUMN base.users.extra_data IS 'Add extra details for users';

CREATE UNIQUE INDEX idx_users_email ON base.users (email);

ALTER TABLE base.users ENABLE ROW LEVEL SECURITY;
GRANT ALL ON base.users TO authenticated;

-- Create workspace_users table
CREATE TABLE base.workspace_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  user_id UUID NOT NULL,
  extra_data JSONB,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now(),
  CONSTRAINT fk_workspace FOREIGN KEY (workspace_id) REFERENCES base.workspaces (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES base.users (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX idx_workspace_users_workspace_user ON base.workspace_users (workspace_id, user_id);

ALTER TABLE base.workspace_users ENABLE ROW LEVEL SECURITY;
GRANT ALL ON base.workspace_users TO authenticated;

-- Create workspace_user_permissions table
CREATE TABLE base.workspace_user_permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  user_id UUID NOT NULL,
  permissions text[] NOT NULL,
  CONSTRAINT fk_workspace FOREIGN KEY (workspace_id) REFERENCES base.workspaces (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES base.users (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX idx_workspace_user_permissions ON base.workspace_user_permissions (workspace_id, user_id);
ALTER TABLE base.workspace_user_permissions ENABLE ROW LEVEL SECURITY;
GRANT ALL ON base.workspace_user_permissions TO authenticated;

-- Create a sample table for RLS testing
CREATE TABLE base.settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    settings_json JSONB,
    workspace_id UUID NOT NULL,
    created_by_id UUID NOT NULL,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now(),
    CONSTRAINT fk_user FOREIGN KEY (created_by_id) REFERENCES base.users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_workspace FOREIGN KEY (workspace_id) REFERENCES base.workspaces (id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX idx_settings_workspace ON base.settings (workspace_id);
CREATE INDEX idx_settings_user ON base.settings (created_by_id);

ALTER TABLE base.settings ENABLE ROW LEVEL SECURITY;
GRANT ALL ON base.settings to authenticated;

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