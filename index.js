require('dotenv').config();
const path = require('path');
const express = require('express');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Telegraf } = require('telegraf');
const axios = require('axios');

// ---- Express & Static ----
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- SQLite3 Setup ----
const dbFile = process.env.DB_PATH || './mydb.sqlite';
const initSQL = fs.readFileSync('database.sql', 'utf8');
const db = new sqlite3.Database(dbFile, err => {
  if (err) {
    console.error('Ошибка открытия базы:', err);
    process.exit(1);
  }
  db.exec(initSQL, err2 => {
    if (err2) {
      console.error('Ошибка инициализации схемы:', err2);
      process.exit(1);
    }
  });
});
// Промисифицируем
const run  = promisify(db.run.bind(db));
const get  = promisify(db.get.bind(db));
const all  = promisify(db.all.bind(db));

// ---- Auth Helper ----
function authenticate(req, res) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    res.sendStatus(401);
    return null;
  }
  try {
    return jwt.verify(h.slice(7), process.env.JWT_SECRET);
  } catch {
    res.sendStatus(403);
    return null;
  }
}

// ---- HTTP API Routes ----
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
  try {
    await run(
      'INSERT INTO users(username, password_hash) VALUES(?, ?)',
      username, hash
    );
    res.sendStatus(201);
  } catch {
    res.sendStatus(409);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await get(
    'SELECT * FROM users WHERE username = ?',
    username
  );
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.sendStatus(401);
  }
  const token = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
  res.json({ token });
});

app.post('/tasks', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  await run(
    'INSERT INTO items(text, user_id) VALUES(?, ?)',
    req.body.text, auth.id
  );
  res.sendStatus(201);
});

app.get('/tasks', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const tasks = await all(
    'SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC',
    auth.id
  );
  res.json(tasks);
});

app.put('/tasks/:id', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const id = +req.params.id;
  if (req.body.text !== undefined) {
    await run(
      'UPDATE items SET text = ? WHERE id = ? AND user_id = ?',
      req.body.text, id, auth.id
    );
  }
  if (req.body.completed !== undefined) {
    await run(
      'UPDATE items SET completed = ? WHERE id = ? AND user_id = ?',
      req.body.completed, id, auth.id
    );
  }
  res.sendStatus(200);
});

app.delete('/tasks/:id', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  await run(
    'DELETE FROM items WHERE id = ? AND user_id = ?',
    +req.params.id, auth.id
  );
  res.sendStatus(204);
});

// ---- Telegram Bot via Webhook ----
const token = process.env.BOT_TOKEN;
const externalUrl = process.env.RENDER_EXTERNAL_URL;
if (!token || !externalUrl) {
  console.error('❌ Нужно задать BOT_TOKEN и RENDER_EXTERNAL_URL в .env');
  process.exit(1);
}

const bot = new Telegraf(token);
const hookPath = `/bot${token}`;
const hookUrl  = `${externalUrl}${hookPath}`;

bot.telegram
  .setWebhook(hookUrl)
  .then(() => console.log(`✅ Webhook установлен: ${hookUrl}`))
  .catch(err => {
    console.error('❌ Ошибка установки webhook:', err);
    process.exit(1);
  });

app.post(hookPath, bot.webhookCallback(hookPath));

const sessions = new Map();
const API_BASE = `http://localhost:${process.env.PORT || 3000}`;

bot.start(ctx => ctx.reply('Привет! Сайт и бот запущены через Webhook.'));
bot.command('register', async ctx => {
  const [, u, p] = ctx.message.text.split(' ');
  if (!u || !p) return ctx.reply('Использование: /register имя пароль');
  try {
    await axios.post(`${API_BASE}/register`, { username: u, password: p });
    ctx.reply('Регистрация выполнена');
  } catch {
    ctx.reply('Ошибка регистрации');
  }
});
bot.command('login', async ctx => {
  const [, u, p] = ctx.message.text.split(' ');
  if (!u || !p) return ctx.reply('Использование: /login имя пароль');
  try {
    const { data } = await axios.post(`${API_BASE}/login`, { username: u, password: p });
    sessions.set(ctx.chat.id, data.token);
    ctx.reply('Вы вошли в систему');
  } catch {
    ctx.reply('Неверные учётные данные');
  }
});
bot.command('tasks', async ctx => {
  const t = sessions.get(ctx.chat.id);
  if (!t) return ctx.reply('Сначала выполните /login');
  try {
    const { data } = await axios.get(`${API_BASE}/tasks`, {
      headers: { Authorization: `Bearer ${t}` }
    });
    const text = data.map(t => `#${t.id}. ${t.text} [${t.completed ? '✓' : ' '}]`).join('\n');
    ctx.reply(text || 'Задач нет');
  } catch {
    ctx.reply('Ошибка получения задач');
  }
});
bot.command('add', async ctx => {
  const t = sessions.get(ctx.chat.id);
  if (!t) return ctx.reply('Сначала выполните /login');
  const text = ctx.message.text.replace('/add', '').trim();
  if (!text) return ctx.reply('Укажите текст задачи');
  try {
    await axios.post(`${API_BASE}/tasks`, { text }, {
      headers: { Authorization: `Bearer ${t}` }
    });
    ctx.reply('Задача добавлена');
  } catch {
    ctx.reply('Ошибка добавления');
  }
});
bot.command('edit', async ctx => {
  const t = sessions.get(ctx.chat.id);
  if (!t) return ctx.reply('Сначала выполните /login');
  const m = ctx.message.text.match(/^\/edit\s+(\d+)\s+(.+)/);
  if (!m) return ctx.reply('Использование: /edit id новый_текст');
  try {
    await axios.put(`${API_BASE}/tasks/${m[1]}`, { text: m[2] }, {
      headers: { Authorization: `Bearer ${t}` }
    });
    ctx.reply(`Задача #${m[1]} обновлена`);
  } catch {
    ctx.reply('Ошибка редактирования');
  }
});
bot.command('done', async ctx => {
  const t = sessions.get(ctx.chat.id);
  if (!t) return ctx.reply('Сначала выполните /login');
  const id = ctx.message.text.split(' ')[1];
  try {
    await axios.put(`${API_BASE}/tasks/${id}`, { completed: 1 }, {
      headers: { Authorization: `Bearer ${t}` }
    });
    ctx.reply(`Задача #${id} отмечена`);
  } catch {
    ctx.reply('Ошибка');
  }
});
bot.command('del', async ctx => {
  const t = sessions.get(ctx.chat.id);
  if (!t) return ctx.reply('Сначала выполните /login');
  const id = ctx.message.text.split(' ')[1];
  try {
    await axios.delete(`${API_BASE}/tasks/${id}`, {
      headers: { Authorization: `Bearer ${t}` }
    });
    ctx.reply(`Задача #${id} удалена`);
  } catch {
    ctx.reply('Ошибка удаления');
  }
});

// ---- Запуск HTTP сервера ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🌐 Сервер и Telegram Webhook слушают порт ${PORT}`);
});
