require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const { Telegraf } = require('telegraf');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

// ==== БД ====
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

// ==== Express ====
const app = express();
app.use(express.json());

// Отдача статических файлов (в том числе index.html)
app.use(express.static(__dirname));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ==== Авторизация ====
function auth(req, res) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).end();
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    res.status(403).end();
    return null;
  }
}

// ==== API ====
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
  try {
    stmts.createUser.run(username, hash);
    res.status(201).end();
  } catch {
    res.status(409).end();
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = stmts.getUserByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).end();
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
  res.json({ token });
});

app.get('/tasks', (req, res) => {
  const user = auth(req, res);
  if (!user) return;
  const tasks = stmts.getTasks.all(user.id);
  res.json(tasks);
});

app.post('/tasks', (req, res) => {
  const user = auth(req, res);
  if (!user) return;
  stmts.createTask.run(req.body.text, user.id);
  res.status(201).end();
});

app.put('/tasks/:id', (req, res) => {
  const user = auth(req, res);
  if (!user) return;
  const id = +req.params.id;
  const { text, completed } = req.body;
  if (text !== undefined) stmts.updateText.run(text, id, user.id);
  if (completed !== undefined) stmts.updateTask.run(completed, id, user.id);
  res.end();
});

app.delete('/tasks/:id', (req, res) => {
  const user = auth(req, res);
  if (!user) return;
  stmts.deleteTask.run(+req.params.id, user.id);
  res.status(204).end();
});

// ==== Telegram Bot ====
const bot = new Telegraf(process.env.BOT_TOKEN);
const sessions = new Map();
const apiUrl = process.env.RENDER_EXTERNAL_URL;

// Подключаем webhook к Express
app.use(bot.webhookCallback(`/bot${process.env.BOT_TOKEN}`));

// Команды
bot.start(ctx => ctx.reply('Добро пожаловать! Используйте /register, /login, /add, /tasks'));
bot.command('register', async ctx => {
  const [ , u, p ] = ctx.message.text.split(' ');
  if (!u || !p) return ctx.reply('Пример: /register user pass');
  try {
    await axios.post(`${apiUrl}/register`, { username: u, password: p });
    ctx.reply('Регистрация успешна');
  } catch {
    ctx.reply('Ошибка регистрации');
  }
});
bot.command('login', async ctx => {
  const [ , u, p ] = ctx.message.text.split(' ');
  try {
    const r = await axios.post(`${apiUrl}/login`, { username: u, password: p });
    sessions.set(ctx.chat.id, r.data.token);
    ctx.reply('Вход выполнен');
  } catch {
    ctx.reply('Ошибка входа');
  }
});
bot.command('add', async ctx => {
  const token = sessions.get(ctx.chat.id);
  const text = ctx.message.text.replace('/add', '').trim();
  if (!token || !text) return ctx.reply('Сначала /login и текст задачи');
  try {
    await axios.post(`${apiUrl}/tasks`, { text }, { headers: { Authorization: `Bearer ${token}` } });
    ctx.reply('Добавлено');
  } catch {
    ctx.reply('Ошибка');
  }
});
bot.command('tasks', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала /login');
  try {
    const r = await axios.get(`${apiUrl}/tasks`, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.data.length) return ctx.reply('Задач нет');
    ctx.reply(r.data.map(t => `${t.id}. ${t.text} [${t.completed ? '✓' : ' '}]`).join('\n'));
  } catch {
    ctx.reply('Ошибка получения');
  }
});

// ==== Запуск ====
const PORT = process.env.PORT || 10000;
app.listen(PORT, async () => {
  const webhookURL = `${apiUrl}/bot${process.env.BOT_TOKEN}`;
  try {
    await bot.telegram.setWebhook(webhookURL);
    console.log(`✅ Webhook установлен: ${webhookURL}`);
  } catch (err) {
    console.error('Ошибка установки Webhook:', err);
  }
  console.log(`Сервер запущен на порту ${PORT}`);
});
