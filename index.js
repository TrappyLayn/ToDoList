require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { Telegraf } = require('telegraf');
const axios = require('axios');

const db = new sqlite3.Database(process.env.DB_PATH);
db.exec(fs.readFileSync('database.sql', 'utf8'));

const port = process.env.PORT || 3000;
const API_BASE = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;

const sessions = new Map();

const bot = new Telegraf(process.env.BOT_TOKEN);

const commands = [
  { command: 'register', description: 'Регистрация: /register имя пароль' },
  { command: 'login',    description: 'Вход: /login имя пароль' },
  { command: 'tasks',    description: 'Список задач' },
  { command: 'add',      description: 'Добавить задачу: /add текст задачи' },
  { command: 'edit',     description: 'Изменить задачу: /edit id новый_текст' },
  { command: 'done',     description: 'Отметить задачу выполненной: /done id' },
  { command: 'del',      description: 'Удалить задачу: /del id' }
];

bot.start(ctx => ctx.reply('Я — ваш To-Do бот!\n\n' + commands.map(c => `/${c.command} — ${c.description}`).join('\n')));
bot.command('help', ctx => ctx.reply('Доступные команды:\n' + commands.map(c => `/${c.command} — ${c.description}`).join('\n')));

bot.command('register', async ctx => {
  const [ , username, password ] = ctx.message.text.split(' ');
  if (!username || !password) return ctx.reply('Использование: /register имя пароль');
  try {
    await axios.post(`${API_BASE}/register`, { username, password });
    ctx.reply('Регистрация успешна');
  } catch {
    ctx.reply('Ошибка регистрации');
  }
});

bot.command('login', async ctx => {
  const [ , username, password ] = ctx.message.text.split(' ');
  if (!username || !password) return ctx.reply('Использование: /login имя пароль');
  try {
    const resp = await axios.post(`${API_BASE}/login`, { username, password });
    sessions.set(ctx.chat.id, resp.data.token);
    ctx.reply('Вход выполнен');
  } catch {
    ctx.reply('Неправильные логин или пароль');
  }
});

bot.command('tasks', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  try {
    const resp = await axios.get(`${API_BASE}/tasks`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const text = resp.data.map(t => `#${t.id}. ${t.text} [${t.completed ? '✓' : ' '}]`).join('\n');
    ctx.reply(text || 'Нет задач');
  } catch {
    ctx.reply('Ошибка получения задач');
  }
});

bot.command('add', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const text = ctx.message.text.replace('/add', '').trim();
  if (!text) return ctx.reply('Укажите текст задачи');
  try {
    await axios.post(`${API_BASE}/tasks`, { text }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply('Задача добавлена');
  } catch {
    ctx.reply('Ошибка добавления');
  }
});

bot.command('edit', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const match = ctx.message.text.match(/^\/edit\s+(\d+)\s+(.+)/);
  if (!match) return ctx.reply('Использование: /edit id новый_текст');
  const [ , id, newText ] = match;
  try {
    await axios.put(`${API_BASE}/tasks/${id}`, { text: newText }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} изменена`);
  } catch {
    ctx.reply('Ошибка изменения');
  }
});

bot.command('done', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const id = ctx.message.text.split(' ')[1];
  try {
    await axios.put(`${API_BASE}/tasks/${id}`, { completed: 1 }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} завершена`);
  } catch {
    ctx.reply('Ошибка');
  }
});

bot.command('del', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const id = ctx.message.text.split(' ')[1];
  try {
    await axios.delete(`${API_BASE}/tasks/${id}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} удалена`);
  } catch {
    ctx.reply('Ошибка удаления');
  }
});

// Webhook для Telegram
const botWebhookPath = `/bot${process.env.BOT_TOKEN}`;
bot.telegram.setWebhook(`${API_BASE}${botWebhookPath}`);

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (req.method === 'POST' && pathname === botWebhookPath) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const update = JSON.parse(body);
        bot.handleUpdate(update);
        res.writeHead(200).end();
      } catch {
        res.writeHead(400).end();
      }
    });
    return;
  }

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
  console.log(`\u{1F680} Сервер запущен на порту ${port}`);
});
