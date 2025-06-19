require('dotenv').config();
const http = require('http');
const fs = require('fs');
const url = require('url');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// ==== Telegram Bot Setup ====
const { Telegraf } = require('telegraf');
const axios = require('axios');

// ==== Database setup ====
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

// ==== HTTP Server ====
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
  console.log(`HTTP-сервер запущен на порту ${port}`);
});

// ==== Telegram Bot ====
const bot = new Telegraf(process.env.BOT_TOKEN);
const API_BASE = `http://localhost:${port}`;
const sessions = new Map();

const commands = [
  { command: 'register', description: 'Регистрация: /register имя пароль' },
  { command: 'login',    description: 'Вход: /login имя пароль' },
  { command: 'tasks',    description: 'Список задач' },
  { command: 'add',      description: 'Добавить задачу: /add текст задачи' },
  { command: 'edit',     description: 'Изменить задачу: /edit id новый_текст' },
  { command: 'done',     description: 'Отметить задачу выполненной: /done id' },
  { command: 'del',      description: 'Удалить задачу: /del id' }
];

async function setupBotCommands() {
  console.log('Доступные команды Telegram-бота:');
  commands.forEach(cmd => {
    console.log(`/${cmd.command} — ${cmd.description}`);
  });
  await bot.telegram.setMyCommands(commands);
}

function getHelpText() {
  return 'Я — ваш To-Do бот!\n\n' + commands.map(cmd => `/${cmd.command} — ${cmd.description}`).join('\n');
}

bot.start(ctx => ctx.reply(getHelpText()));
bot.command('help', ctx => ctx.reply(getHelpText()));

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

setupBotCommands()
  .then(() => {
    console.log('Запускаю бота...');
    return bot.launch();
  })
  .then(() => {
    console.log('✅ Бот Telegram запущен');
  })
  .catch(err => {
    console.error('❌ Ошибка запуска бота:', err.message);
  });

