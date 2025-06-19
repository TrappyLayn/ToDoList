require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Telegraf } = require('telegraf');
const axios = require('axios');

// ==== Configuration ==== 
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || 'database.sqlite';
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 10;
const BOT_TOKEN = process.env.BOT_TOKEN;
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL;

if (!JWT_SECRET || !BOT_TOKEN) {
  console.error('❌ Не заданы обязательные ENV: JWT_SECRET или BOT_TOKEN');
  process.exit(1);
}

// ==== Database setup ==== 
const db = new Database(DB_PATH);
if (fs.existsSync('database.sql')) {
  db.exec(fs.readFileSync('database.sql', 'utf8'));
}
const stmts = {
  createUser:    db.prepare('INSERT INTO users(username, password_hash) VALUES(?, ?)'),
  getUserByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  createTask:    db.prepare('INSERT INTO items(text, user_id) VALUES(?, ?)'),
  getTasks:      db.prepare('SELECT * FROM items WHERE user_id = ? ORDER BY created_at DESC'),
  updateText:    db.prepare('UPDATE items SET text = ? WHERE id = ? AND user_id = ?'),
  updateTask:    db.prepare('UPDATE items SET completed = ? WHERE id = ? AND user_id = ?'),
  deleteTask:    db.prepare('DELETE FROM items WHERE id = ? AND user_id = ?')
};

// ==== Helper functions ==== 
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.sendStatus(401);
  }
  try {
    const payload = jwt.verify(header.split(' ')[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.sendStatus(403);
  }
}

// ==== Express server ==== 
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files if needed
app.use(express.static(path.join(__dirname, 'public')));

// === Web routes ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// === Auth routes ===
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.sendStatus(400);
  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  try {
    stmts.createUser.run(username, hash);
    res.sendStatus(201);
  } catch {
    res.sendStatus(409);
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = stmts.getUserByName.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.sendStatus(401);
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  res.json({ token });
});

// === Task API ===
app.post('/tasks', authMiddleware, (req, res) => {
  const { text } = req.body;
  stmts.createTask.run(text, req.user.id);
  res.sendStatus(201);
});

app.get('/tasks', authMiddleware, (req, res) => {
  const tasks = stmts.getTasks.all(req.user.id);
  res.json(tasks);
});

app.put('/tasks/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const { text, completed } = req.body;
  if (text !== undefined) stmts.updateText.run(text, id, req.user.id);
  if (completed !== undefined) stmts.updateTask.run(completed, id, req.user.id);
  res.sendStatus(200);
});

app.delete('/tasks/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  stmts.deleteTask.run(id, req.user.id);
  res.sendStatus(204);
});

// ==== Telegram Bot Webhook ==== 
const bot = new Telegraf(BOT_TOKEN);
const hookPath = `/bot${BOT_TOKEN}`;

app.post(hookPath, (req, res) => {
  bot.handleUpdate(req.body, res)
    .catch(err => {
      console.error('Ошибка Webhook:', err);
      res.sendStatus(500);
    });
});

(async () => {
  try {
    await bot.telegram.deleteWebhook();
    const hookUrl = `${EXTERNAL_URL}${hookPath}`;
    await bot.telegram.setWebhook(hookUrl);
    console.log('✅ Webhook установлен:', hookUrl);

    // Setup commands
    const commands = [
      { command: 'register', description: 'Регистрация: /register имя пароль' },
      { command: 'login', description: 'Вход: /login имя пароль' },
      { command: 'tasks', description: 'Список задач' },
      { command: 'add', description: 'Добавить задачу: /add текст задачи' },
      { command: 'edit', description: 'Изменить задачу: /edit id новый_текст' },
      { command: 'done', description: 'Отметить задачу выполненной: /done id' },
      { command: 'del', description: 'Удалить задачу: /del id' },
      { command: 'help', description: 'Помощь' }
    ];
    await bot.telegram.setMyCommands(commands);

    // Bot handlers
    const API_BASE = `http://localhost:${PORT}`;
    const sessions = new Map();

    bot.start(ctx => ctx.reply('Я — ваш To-Do бот! Используйте /help для списка команд.'));
    bot.help(ctx => ctx.reply('Список команд: ' + commands.map(c => `/${c.command}`).join(', ')));

    bot.command('register', async ctx => {
      const [_, username, password] = ctx.message.text.split(' ');
      if (!username || !password) return ctx.reply('Использование: /register имя пароль');
      try {
        await axios.post(`${API_BASE}/register`, { username, password });
        ctx.reply('Регистрация успешна');
      } catch {
        ctx.reply('Ошибка регистрации');
      }
    });

    bot.command('login', async ctx => {
      const [_, username, password] = ctx.message.text.split(' ');
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
        const resp = await axios.get(`${API_BASE}/tasks`, { headers: { Authorization: `Bearer ${token}` } });
        const text = resp.data.map(t => `#${t.id}. ${t.text} [${t.completed ? '✓' : ' '}]`).join('\n');
        ctx.reply(text || 'Нет задач');
      } catch {
        ctx.reply('Ошибка получения задач');
      }
    });

    bot.command('add', async ctx => {
      const token = sessions.get(ctx.chat.id);
      if (!token) return ctx.reply('Сначала войдите через /login');
      const text = ctx.message.text.replace(/\/add\s+/, '').trim();
      if (!text) return ctx.reply('Укажите текст задачи');
      try {
        await axios.post(`${API_BASE}/tasks`, { text }, { headers: { Authorization: `Bearer ${token}` } });
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
      const [_, id, newText] = match;
      try {
        await axios.put(`${API_BASE}/tasks/${id}`, { text: newText }, { headers: { Authorization: `Bearer ${token}` } });
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
        await axios.put(`${API_BASE}/tasks/${id}`, { completed: 1 }, { headers: { Authorization: `Bearer ${token}` } });
        ctx.reply(`Задача #${id} завершена`);
      } catch {
        ctx.reply('Ошибка выполнения');
      }
    });

    bot.command('del', async ctx => {
      const token = sessions.get(ctx.chat.id);
      if (!token) return ctx.reply('Сначала войдите через /login');
      const id = ctx.message.text.split(' ')[1];
      try {
        await axios.delete(`${API_BASE}/tasks/${id}`, { headers: { Authorization: `Bearer ${token}` } });
        ctx.reply(`Задача #${id} удалена`);
      } catch {
        ctx.reply('Ошибка удаления');
      }
    });

    app.listen(PORT, () => console.log(`🌐 Сервер запущен на порту ${PORT}`));
  } catch (err) {
    console.error('❌ Ошибка при настройке вебхука:', err);
    process.exit(1);
  }
})();
