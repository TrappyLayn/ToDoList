require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Telegraf } = require('telegraf');
const axios = require('axios');

const app = express();
app.use(express.json());

const db = new sqlite3.Database(process.env.DB_PATH);
db.serialize(() => {
  const schema = fs.readFileSync('database.sql', 'utf8');
  db.exec(schema);
});

// ==== API Endpoints ====
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.sendStatus(401);
  try {
    req.user = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
  db.run('INSERT INTO users(username, password_hash) VALUES(?, ?)', [username, hash], function(err) {
    if (err) return res.sendStatus(409);
    res.sendStatus(201);
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.sendStatus(401);
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
    res.json({ token });
  });
});

app.get('/tasks', authMiddleware, (req, res) => {
  db.all('SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.post('/tasks', authMiddleware, (req, res) => {
  db.run('INSERT INTO items(text, user_id) VALUES(?, ?)', [req.body.text, req.user.id], err => {
    if (err) return res.sendStatus(500);
    res.sendStatus(201);
  });
});

app.put('/tasks/:id', authMiddleware, (req, res) => {
  const { text, completed } = req.body;
  if (text !== undefined) {
    db.run('UPDATE items SET text = ? WHERE id = ? AND user_id = ?', [text, req.params.id, req.user.id]);
  }
  if (completed !== undefined) {
    db.run('UPDATE items SET completed = ? WHERE id = ? AND user_id = ?', [completed, req.params.id, req.user.id]);
  }
  res.sendStatus(200);
});

app.delete('/tasks/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM items WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  res.sendStatus(204);
});

app.get('/', (req, res) => {
  res.send('Сервер работает. To-Do Bot');
});

// ==== Telegram Bot ====
const bot = new Telegraf(process.env.BOT_TOKEN);
const api = process.env.RENDER_EXTERNAL_URL;
const sessions = new Map();

bot.start(ctx => ctx.reply('Привет! Используй /register и /login'));
bot.command('register', async ctx => {
  const [ , u, p ] = ctx.message.text.split(' ');
  if (!u || !p) return ctx.reply('Использование: /register имя пароль');
  try {
    await axios.post(`${api}/register`, { username: u, password: p });
    ctx.reply('Регистрация успешна');
  } catch {
    ctx.reply('Ошибка регистрации');
  }
});
bot.command('login', async ctx => {
  const [ , u, p ] = ctx.message.text.split(' ');
  try {
    const r = await axios.post(`${api}/login`, { username: u, password: p });
    sessions.set(ctx.chat.id, r.data.token);
    ctx.reply('Вход успешен');
  } catch {
    ctx.reply('Ошибка входа');
  }
});
bot.command('tasks', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  try {
    const r = await axios.get(`${api}/tasks`, { headers: { Authorization: `Bearer ${token}` } });
    ctx.reply(r.data.map(t => `#${t.id} ${t.text} ${t.completed ? '✓' : ''}`).join('\n') || 'Нет задач');
  } catch {
    ctx.reply('Ошибка получения');
  }
});
bot.command('add', async ctx => {
  const token = sessions.get(ctx.chat.id);
  const text = ctx.message.text.replace('/add', '').trim();
  if (!token || !text) return ctx.reply('Используйте /add текст');
  try {
    await axios.post(`${api}/tasks`, { text }, { headers: { Authorization: `Bearer ${token}` } });
    ctx.reply('Добавлено');
  } catch {
    ctx.reply('Ошибка');
  }
});

// ==== Запуск ====
app.use(bot.webhookCallback(`/bot${process.env.BOT_TOKEN}`));
bot.telegram.setWebhook(`${api}/bot${process.env.BOT_TOKEN}`)
  .then(() => console.log(`✅ Webhook установлен: ${api}/bot${process.env.BOT_TOKEN}`))
  .catch(console.error);

app.listen(process.env.PORT, () => {
  console.log(`🚀 Сервер на порту ${process.env.PORT}`);
});