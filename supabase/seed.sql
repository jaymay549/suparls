-- Insert a sample workspace
INSERT INTO base.workspaces (id, name, slug, extra_data)
VALUES 
  ('11111111-1111-1111-1111-111111111111', 'Demo Workspace', 'demo-workspace', '{"description": "A demo workspace for testing"}');

-- Insert a sample user
INSERT INTO base.users (id, email, extra_data)
VALUES 
  ('22222222-2222-2222-2222-222222222222', 'demo@example.com', '{"name": "Demo User", "avatar_url": "https://example.com/avatar.png"}');

-- Link the user to the workspace
INSERT INTO base.workspace_users (workspace_id, user_id, extra_data)
VALUES 
  ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '{"role": "admin"}');

-- Add permissions for the user
INSERT INTO base.workspace_user_permissions (workspace_id, user_id, permissions)
VALUES 
  ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 
   ARRAY[
     'workspaces.read', 
     'workspaces.update', 
     'users.read', 
     'users.create', 
     'users.update', 
     'users.delete',
     'settings.read',
     'settings.create',
     'settings.update',
     'settings.delete'
   ]);

-- Insert a sample settings record
INSERT INTO base.settings (workspace_id, created_by_id, settings_json)
VALUES 
  ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 
   '{"theme": "dark", "notifications": {"email": true, "push": false}}');
