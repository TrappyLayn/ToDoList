require('dotenv').config();
const http = require('http');
const fs = require('fs');
const url = require('url');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const db = new Database(process.env.DB_PATH);
db.exec(fs.readFileSync('database.sql', 'utf8'));

const stmts = {
  createUser: db.prepare('INSERT INTO users(username, password_hash) VALUES(?, ?)'),
  getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  createTask: db.prepare('INSERT INTO items(text, user_id) VALUES(?, ?)'),
  getTasks: db.prepare('SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC'),
  updateText: db.prepare('UPDATE items SET text = ? WHERE id = ? AND user_id = ?'),
  updateTask: db.prepare('UPDATE items SET completed = ? WHERE id = ? AND user_id = ?'),
  deleteTask: db.prepare('DELETE FROM items WHERE id = ? AND user_id = ?')
};

function parseBody(req) {
  return new Promise(resolve => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => resolve(JSON.parse(data || '{}')));
  });
}

function authenticate(req, res) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.writeHead(401).end();
    return null;
  }
  try {
    return jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
  } catch {
    res.writeHead(403).end();
    return null;
  }
}

// Экспортируем только логику, не сервер
module.exports = { db, stmts, bcrypt, jwt };

// Сервер запускаем только если файл запущен напрямую
if (require.main === module) {
  const port = process.env.PORT || 3000;
  const server = http.createServer(async (req, res) => {
    const path = url.parse(req.url).pathname;

    if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync('index.html'));
      return;
    }

    if (req.method === 'POST' && path === '/register') {
      const { username, password } = await parseBody(req);
      const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
      try {
        stmts.createUser.run(username, hash);
        res.writeHead(201).end();
      } catch {
        res.writeHead(409).end();
      }
      return;
    }

    if (req.method === 'POST' && path === '/login') {
      const { username, password } = await parseBody(req);
      const user = stmts.getUserByUsername.get(username);
      if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        res.writeHead(401).end();
        return;
      }
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token }));
      return;
    }

    const auth = authenticate(req, res);
    if (!auth) return;

    if (req.method === 'POST' && path === '/tasks') {
      const { text } = await parseBody(req);
      stmts.createTask.run(text, auth.id);
      res.writeHead(201).end();
      return;
    }
    if (req.method === 'GET' && path === '/tasks') {
      const tasks = stmts.getTasks.all(auth.id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(tasks));
      return;
    }
    if (req.method === 'PUT' && path.startsWith('/tasks/')) {
      const id = +path.split('/')[2];
      const { text, completed } = await parseBody(req);
      if (text !== undefined) stmts.updateText.run(text, id, auth.id);
      if (completed !== undefined) stmts.updateTask.run(completed, id, auth.id);
      res.writeHead(200).end();
      return;
    }
    if (req.method === 'DELETE' && path.startsWith('/tasks/')) {
      const id = +path.split('/')[2];
      stmts.deleteTask.run(id, auth.id);
      res.writeHead(204).end();
      return;
    }

    res.writeHead(404).end();
  });

  server.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}
