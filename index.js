require('dotenv').config({ path: './dd.env' });
const http = require('http'), fs = require('fs'), url = require('url');
const Database = require('better-sqlite3'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');

const db = new Database(process.env.DB_PATH);
db.exec(fs.readFileSync('database.sql', 'utf8'));

const stmts = {
  createUser: db.prepare('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)'),
  getUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  createTask: db.prepare('INSERT INTO items(text,user_id) VALUES(?,?)'),
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
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    res.writeHead(401).end(); return null;
  }
  try { return jwt.verify(h.split(' ')[1], process.env.JWT_SECRET); }
  catch { res.writeHead(403).end(); return null; }
}

function renderRows(tasks) {
  return tasks.map((t, i) => `
    <tr>
      <td>${i+1}</td>
      <td>${t.text}</td>
      <td>${t.completed ? '✓' : ''}</td>
      <td>
        <button onclick="editTask(${t.id}, '${t.text.replace(/'/g,"\\'")}')">✏️</button>
        <button onclick="toggleTask(${t.id}, ${t.completed})">✔️</button>
        <button onclick="deleteTask(${t.id})">🗑️</button>
      </td>
    </tr>`).join('');
}

async function handler(req, res) {
  const p = url.parse(req.url).pathname;
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.end();

  if (p === '/' && req.method === 'GET') {
    res.writeHead(200, {'Content-Type':'text/html'}).end(fs.readFileSync('index.html','utf8'));
  }
  else if (p === '/register' && req.method === 'POST') {
    const { user, email, pass } = await parseBody(req);
    if (!user||!email||!pass) { res.writeHead(400).end(); return; }
    if (stmts.getUserByEmail.get(email)) { res.writeHead(409).end(); return; }
    const h = bcrypt.hashSync(pass, +process.env.BCRYPT_ROUNDS);
    stmts.createUser.run(user, email, h);
    res.writeHead(201).end();
  }
  else if (p === '/login' && req.method === 'POST') {
    const { email, pass } = await parseBody(req);
    const u = stmts.getUserByEmail.get(email);
    if (!u || !bcrypt.compareSync(pass, u.password_hash)) {
      res.writeHead(401).end(); return;
    }
    const token = jwt.sign({id:u.id,username:u.username}, process.env.JWT_SECRET, {expiresIn:process.env.JWT_EXPIRES_IN});
    res.writeHead(200, {'Content-Type':'application/json'}).end(JSON.stringify({token,u}));
  }
  else {
    const user = authenticate(req, res); if (!user) return;
    if (p === '/tasks' && req.method === 'GET') {
      const rows = stmts.getTasks.all(user.id);
      res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({rows:renderRows(rows)}));
    }
    else if (p === '/tasks' && req.method === 'POST') {
      const { text } = await parseBody(req); stmts.createTask.run(text, user.id);
      res.writeHead(201).end();
    }
    else if (p.startsWith('/tasks/') && req.method === 'PUT') {
      const id = +p.split('/')[2], b = await parseBody(req);
      if (b.text !== undefined) stmts.updateText.run(b.text, id, user.id);
      else stmts.updateTask.run(b.completed?0:1, id, user.id);
      res.writeHead(200).end();
    }
    else if (p.startsWith('/tasks/') && req.method === 'DELETE') {
      stmts.deleteTask.run(+p.split('/')[2], user.id); res.writeHead(200).end();
    }
    else res.writeHead(404).end();
  }
}

http.createServer(handler).listen(process.env.PORT||3000, () => {
  console.log('Server on port ' + (process.env.PORT||3000));
});
