// server.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const fs = require('fs');
const url = require('url');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Telegraf } = require('telegraf');
const axios = require('axios');

// ==== Express Setup ====
const app = express();
app.use(express.json());

// ==== Serve your frontend ====
app.use(express.static(path.join(__dirname, 'public')));

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
    res.sendStatus(401);
    return null;
  }
  try {
    return jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
  } catch {
    res.sendStatus(403);
    return null;
  }
}

// ==== HTTP API ====
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, +process.env.BCRYPT_ROUNDS);
  try {
    stmts.createUser.run(username, hash);
    res.sendStatus(201);
  } catch {
    res.sendStatus(409);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = stmts.getUserByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.sendStatus(401);
  }
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
  res.json({ token });
});

app.post('/tasks', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const { text } = req.body;
  stmts.createTask.run(text, auth.id);
  res.sendStatus(201);
});

app.get('/tasks', (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const tasks = stmts.getTasks.all(auth.id);
  res.json(tasks);
});

app.put('/tasks/:id', async (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const id = +req.params.id;
  const { text, completed } = req.body;
  if (text !== undefined) stmts.updateText.run(text, id, auth.id);
  if (completed !== undefined) stmts.updateTask.run(completed, id, auth.id);
  res.sendStatus(200);
});

app.delete('/tasks/:id', (req, res) => {
  const auth = authenticate(req, res);
  if (!auth) return;
  const id = +req.params.id;
  stmts.deleteTask.run(id, auth.id);
  res.sendStatus(204);
});

// ==== Telegram Bot via Webhook ====
const token = process.env.BOT_TOKEN;
if (!token) {
  console.error('❌ BOT_TOKEN не задан');
  process.exit(1);
}

// Render сам выставляет эту переменную вида https://<your-app>.onrender.com
const externalUrl = process.env.RENDER_EXTERNAL_URL;
if (!externalUrl) {
  console.error('❌ RENDER_EXTERNAL_URL не задан');
  process.exit(1);
}

const bot = new Telegraf(token);

// Устанавливаем Webhook у Telegram
const hookPath = `/bot${token}`;
const hookUrl  = `${externalUrl}${hookPath}`;
bot.telegram
  .setWebhook(hookUrl)
  .then(() => console.log(`✅ Вебхук установлен на ${hookUrl}`))
  .catch(err => {
    console.error('❌ Не удалось установить вебхук:', err);
    process.exit(1);
  });

// Монтируем callback от Telegram в Express
app.post(hookPath, bot.webhookCallback(hookPath));

// Логика самого бота
const sessions = new Map();
const API_BASE = `http://localhost:${process.env.PORT || 3000}`;

bot.start(ctx => ctx.reply('Привет! Сайт и бот запущены через Webhook.'));
bot.command('register', async ctx => {
  const [, user, pass] = ctx.message.text.split(' ');
  if (!user || !pass) return ctx.reply('Использование: /register имя пароль');
  try {
    await axios.post(`${API_BASE}/register`, { username: user, password: pass });
    ctx.reply('Регистрация успешна');
  } catch {
    ctx.reply('Ошибка регистрации');
  }
});
// … все остальные команды точно так же, только без bot.launch()

// ==== Запуск сервера ====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🌐 Сервер и бот слушают порт ${PORT}`);
});
