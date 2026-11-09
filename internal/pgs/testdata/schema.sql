-- The table definitions below are copied verbatim from picosh/pico,
-- pkg/apps/pgs/db/sqlite.go (sqliteSchema), https://github.com/picosh/pico
-- They are used only as a test fixture. This project is not affiliated with or endorsed by pico.sh.
--
-- The original work is licensed as follows:
--
-- MIT License
--
-- Copyright (c) 2022 pico.sh LLC
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

CREATE TABLE IF NOT EXISTS app_users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS public_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	public_key TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (user_id, public_key),
	CONSTRAINT public_keys_user_id_fk
		FOREIGN KEY(user_id) REFERENCES app_users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	project_dir TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	acl BLOB DEFAULT '{"data": [], "type": "public"}' NOT NULL,
	blocked TEXT NOT NULL DEFAULT '',
	UNIQUE (user_id, name),
	CONSTRAINT projects_user_id_fk
		FOREIGN KEY(user_id) REFERENCES app_users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS feature_flags (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	data BLOB DEFAULT '{}' NOT NULL,
	payment_history_id INTEGER,
	CONSTRAINT feature_flags_user_id_fk
		FOREIGN KEY(user_id) REFERENCES app_users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS form_entries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	data BLOB NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT form_entries_user_id_fk
		FOREIGN KEY(user_id) REFERENCES app_users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
);
