require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(process.env.DB_PATH);

// Инициализация базы данных
const initSql = fs.readFileSync('database.sql', 'utf8');
db.exec(initSql);

const port = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (req.method === 'GET') {
    if (pathname === '/' || pathname === '/index.html') {
      const html = fs.readFileSync('index.html');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }
    if (pathname.startsWith('/static/')) {
      const filePath = path.join(__dirname, pathname);
      if (fs.existsSync(filePath)) {
        const ext = path.extname(filePath).toLowerCase();
        const contentType = {
          '.js': 'text/javascript',
          '.css': 'text/css',
          '.png': 'image/png',
          '.jpg': 'image/jpeg'
        }[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(fs.readFileSync(filePath));
      } else {
        res.writeHead(404).end();
      }
      return;
    }
  }

  const parseBody = () => new Promise(resolve => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => resolve(JSON.parse(data || '{}')));
  });

  const authenticate = () => {
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
  };

  // API endpoints
  if (req.method === 'POST' && pathname === '/register') {
    const { username, password } = await parseBody();
    const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
    db.run('INSERT INTO users(username, password_hash) VALUES(?, ?)', [username, hash], function (err) {
      if (err) {
        res.writeHead(409).end();
      } else {
        res.writeHead(201).end();
      }
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/login') {
    const { username, password } = await parseBody();
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err || !user || !bcrypt.compareSync(password, user.password_hash)) {
        res.writeHead(401).end();
        return;
      }
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token }));
    });
    return;
  }

  const auth = authenticate();
  if (!auth) return;

  if (req.method === 'POST' && pathname === '/tasks') {
    const { text } = await parseBody();
    db.run('INSERT INTO items(text, user_id) VALUES(?, ?)', [text, auth.id], function (err) {
      if (err) res.writeHead(500).end();
      else res.writeHead(201).end();
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/tasks') {
    db.all('SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC', [auth.id], (err, rows) => {
      if (err) res.writeHead(500).end();
      else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(rows));
      }
    });
    return;
  }

  if (req.method === 'PUT' && pathname.startsWith('/tasks/')) {
    const id = +pathname.split('/')[2];
    const { text, completed } = await parseBody();
    if (text !== undefined) {
      db.run('UPDATE items SET text = ? WHERE id = ? AND user_id = ?', [text, id, auth.id]);
    }
    if (completed !== undefined) {
      db.run('UPDATE items SET completed = ? WHERE id = ? AND user_id = ?', [completed, id, auth.id]);
    }
    res.writeHead(200).end();
    return;
  }

  if (req.method === 'DELETE' && pathname.startsWith('/tasks/')) {
    const id = +pathname.split('/')[2];
    db.run('DELETE FROM items WHERE id = ? AND user_id = ?', [id, auth.id], function (err) {
      if (err) res.writeHead(500).end();
      else res.writeHead(204).end();
    });
    return;
  }

  res.writeHead(404).end();
});

server.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});
