CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS employees (
  id UUID PRIMARY KEY,
  data_enc TEXT NOT NULL,
  photo_key TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT NOT NULL REFERENCES users(id),
  approval_status TEXT NOT NULL DEFAULT 'pending' CHECK (approval_status IN ('pending', 'approved', 'rejected')),
  approved_by BIGINT REFERENCES users(id),
  approved_at TIMESTAMPTZ,
  rejected_by BIGINT REFERENCES users(id),
  rejected_at TIMESTAMPTZ,
  rejection_reason TEXT
);
CREATE INDEX IF NOT EXISTS employees_approval_created_idx ON employees (approval_status, created_at);
CREATE INDEX IF NOT EXISTS employees_creator_idx ON employees (created_by, created_at);

CREATE TABLE IF NOT EXISTS documents (
  id UUID PRIMARY KEY,
  employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  storage_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  byte_size BIGINT NOT NULL CHECK (byte_size > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS documents_employee_idx ON documents (employee_id, created_at);

CREATE TABLE IF NOT EXISTS approval_events (
  id BIGSERIAL PRIMARY KEY,
  employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  actor_id BIGINT NOT NULL REFERENCES users(id),
  action TEXT NOT NULL CHECK (action IN ('submitted', 'approved', 'rejected')),
  comment TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS approval_events_employee_idx ON approval_events (employee_id, created_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip_hash TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  window_started TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
