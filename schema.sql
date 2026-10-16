CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(40) NOT NULL UNIQUE,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'participant'
    CHECK (role IN ('participant','curator','admin')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  discord_id VARCHAR(40) UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tests (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS questions (
  id BIGSERIAL PRIMARY KEY,
  test_id BIGINT NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
  position INTEGER NOT NULL DEFAULT 0,
  category VARCHAR(80) NOT NULL DEFAULT 'ОБЩИЕ ЗНАНИЯ',
  question_text TEXT NOT NULL,
  answers JSONB NOT NULL,
  correct_index INTEGER NOT NULL CHECK (correct_index >= 0 AND correct_index <= 7),
  points INTEGER NOT NULL DEFAULT 1 CHECK (points > 0 AND points <= 100)
);

CREATE TABLE IF NOT EXISTS vyshka_entries (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  position INTEGER NOT NULL DEFAULT 0,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attempts (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  test_id BIGINT REFERENCES tests(id) ON DELETE SET NULL,
  test_title VARCHAR(120) NOT NULL,
  score INTEGER NOT NULL DEFAULT 0,
  max_score INTEGER NOT NULL DEFAULT 0,
  correct_count INTEGER NOT NULL DEFAULT 0,
  question_count INTEGER NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'completed'
    CHECK (status IN ('in_progress','completed','reviewed')),
  curator_note TEXT NOT NULL DEFAULT '',
  reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  reviewed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attempt_answers (
  id BIGSERIAL PRIMARY KEY,
  attempt_id BIGINT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  question_id BIGINT REFERENCES questions(id) ON DELETE SET NULL,
  question_text TEXT NOT NULL,
  selected_index INTEGER NOT NULL,
  correct_index INTEGER NOT NULL,
  is_correct BOOLEAN NOT NULL,
  points_awarded INTEGER NOT NULL DEFAULT 0,
  max_points INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_questions_test ON questions(test_id, position);
CREATE INDEX IF NOT EXISTS idx_attempts_user ON attempts(user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_status ON attempts(status, started_at DESC);
