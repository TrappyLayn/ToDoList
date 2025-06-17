require('dotenv').config();
const { Telegraf } = require('telegraf');
const axios = require('axios');

const bot = new Telegraf(process.env.BOT_TOKEN);
const API_BASE = `http://localhost:${process.env.PORT || 3000}`;

// Сессии токенов по chatId
const sessions = new Map();

// Описание команд
const commands = [
  { command: 'register', description: 'Регистрация: /register имя пароль' },
  { command: 'login',    description: 'Вход: /login имя пароль' },
  { command: 'tasks',    description: 'Список задач' },
  { command: 'add',      description: 'Добавить задачу: /add текст задачи' },
  { command: 'edit',     description: 'Изменить задачу: /edit id новый_текст' },
  { command: 'done',     description: 'Отметить задачу выполненной: /done id' },
  { command: 'del',      description: 'Удалить задачу: /del id' }
];

// При запуске выводим команды в консоль и устанавливаем их в Telegram
async function setupBotCommands() {
  console.log('Доступные команды Telegram-бота:');
  commands.forEach(cmd => {
    console.log(`/${cmd.command} — ${cmd.description}`);
  });
  await bot.telegram.setMyCommands(commands);
}

// Приветствие с перечнем команд
function getHelpText() {
  return (
    'Я — ваш To-Do бот!\n\n' +
    commands.map(cmd => `/${cmd.command} — ${cmd.description}`).join('\n')
  );
}

bot.start(ctx => {
  ctx.reply(getHelpText());
});

bot.command('help', ctx => {
  ctx.reply(getHelpText());
});

bot.command('register', async ctx => {
  const parts = ctx.message.text.split(' ');
  if (parts.length !== 3) {
    return ctx.reply('Использование: /register имя пароль');
  }
  const [ , username, password ] = parts;
  try {
    await axios.post(`${API_BASE}/register`, { username, password });
    ctx.reply('Регистрация успешна, войдите через /login');
  } catch (e) {
    ctx.reply('Ошибка регистрации: возможно, пользователь уже существует');
  }
});

bot.command('login', async ctx => {
  const parts = ctx.message.text.split(' ');
  if (parts.length !== 3) {
    return ctx.reply('Использование: /login имя пароль');
  }
  const [ , username, password ] = parts;
  try {
    const resp = await axios.post(`${API_BASE}/login`, { username, password });
    const token = resp.data.token;
    sessions.set(ctx.chat.id, token);
    ctx.reply('Вход выполнен успешно');
  } catch (e) {
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
    if (!resp.data.length) return ctx.reply('Нет задач');
    const text = resp.data.map(t => `#${t.id}. ${t.text} [${t.completed ? '✓' : ' '}]`).join('\n');
    ctx.reply(text);
  } catch {
    ctx.reply('Ошибка получения задач');
  }
});

bot.command('add', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const text = ctx.message.text.replace('/add', '').trim();
  if (!text) return ctx.reply('Укажите текст: /add Купить хлеб');
  try {
    await axios.post(`${API_BASE}/tasks`, { text }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply('Задача добавлена');
  } catch {
    ctx.reply('Ошибка добавления задачи');
  }
});

// Новая команда: изменение задачи
bot.command('edit', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const match = ctx.message.text.match(/^\/edit\s+(\d+)\s+(.+)/);
  if (!match) return ctx.reply('Использование: /edit id новый_текст');
  const id = Number(match[1]);
  const newText = match[2].trim();
  if (!id || !newText) return ctx.reply('Использование: /edit id новый_текст');
  try {
    await axios.put(`${API_BASE}/tasks/${id}`, { text: newText }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} изменена`);
  } catch {
    ctx.reply('Ошибка изменения задачи (возможно, такой задачи нет)');
  }
});

bot.command('done', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const id = Number(ctx.message.text.split(' ')[1]);
  if (!id) return ctx.reply('Укажите ID: /done 2');
  try {
    await axios.put(`${API_BASE}/tasks/${id}`, { completed: 1 }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} отмечена как выполненная`);
  } catch {
    ctx.reply('Ошибка обновления задачи');
  }
});

bot.command('del', async ctx => {
  const token = sessions.get(ctx.chat.id);
  if (!token) return ctx.reply('Сначала войдите через /login');
  const id = Number(ctx.message.text.split(' ')[1]);
  if (!id) return ctx.reply('Укажите ID: /del 3');
  try {
    await axios.delete(`${API_BASE}/tasks/${id}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    ctx.reply(`Задача #${id} удалена`);
  } catch {
    ctx.reply('Ошибка удаления задачи');
  }
});

// Запуск бота с установкой команд
setupBotCommands().then(() => {
  bot.launch();
  console.log('Bot started');
});
