const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MAX_BODY = 1_000_000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify({
      users: [],
      memories: [],
      matches: [],
      questions: [],
      choices: [],
      reports: [],
      blocks: [],
      sessions: []
    }, null, 2)
  );
}

function loadDb() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDb(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function id() {
  return crypto.randomUUID();
}

function now() {
  return new Date().toISOString();
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const actual = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return crypto.timingSafeEqual(
    Buffer.from(actual, 'hex'),
    Buffer.from(hash, 'hex')
  );
}

function sanitizeMemory(m) {
  return {
    id: m.id,
    name: m.name,
    category: m.category,
    year: m.year,
    location: m.location,
    relationship: m.relationship,
    title: m.title,
    content: m.content,
    question: m.question,
    createdAt: m.createdAt
  };
}

function send(res, status, data, headers = {}) {
  const body = JSON.stringify(data);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });

  res.end(body);
}

function html(res, file) {
  fs.readFile(path.join(ROOT, file), (err, data) => {
    if (err) {
      return send(res, 404, {
        error: 'Not found'
      });
    }

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8'
    });

    res.end(data);
  });
}

function parseCookies(req) {
  const out = {};

  (req.headers.cookie || '').split(';').forEach(pair => {
    const i = pair.indexOf('=');

    if (i > -1) {
      out[pair.slice(0, i).trim()] =
        decodeURIComponent(pair.slice(i + 1).trim());
    }
  });

  return out;
}

function sessionUser(req, db) {
  const token = parseCookies(req).echo_session;

  if (!token) return null;

  const session = db.sessions.find(
    s =>
      s.token === token &&
      new Date(s.expiresAt) > new Date()
  );

  if (!session) return null;

  return (
    db.users.find(u => u.id === session.userId) ||
    null
  );
}

function sessionCookie(token) {
  return `echo_session=${encodeURIComponent(
    token
  )}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`;
}

function clearCookie() {
  return 'echo_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0';
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';

    req.on('data', chunk => {
      raw += chunk;

      if (Buffer.byteLength(raw) > MAX_BODY) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

function text(v, max = 5000) {
  return typeof v === 'string'
    ? v.trim().slice(0, max)
    : '';
}

function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    createdAt: u.createdAt
  };
}

function makeDemoDb() {
  const db = loadDb();

  if (db.memories.length) return;

  const demoUser = {
    id: id(),
    name: 'Demo',
    email: 'demo@echo.local',
    salt: '',
    passwordHash: '',
    createdAt: now(),
    settings: {
      anonymous: true,
      allowMatching: true,
      visibility: 'archive'
    }
  };

  db.users.push(demoUser);

  db.memories.push(
    {
      id: id(),
      userId: demoUser.id,
      name: 'Moonlight',
      category: 'Friendship',
      year: '2021',
      location: 'School',
      relationship: 'Friend',
      nickname: '',
      title: 'The day we stopped talking',
      content:
        'We were best friends in middle school. One day after an argument, we stopped talking. I always wondered whether she actually hated me or whether something else happened.',
      question:
        'Did she remember that day the same way I did?',
      privateDetails: '',
      createdAt: now(),
      demo: true
    },

    {
      id: id(),
      userId: demoUser.id,
      name: 'NorthStar',
      category: 'Lost Connection',
      year: '2019',
      location: 'School trip',
      relationship: 'Acquaintance',
      nickname: '',
      title: 'An afternoon away from the group',
      content:
        "There was someone I met during a school trip years ago. We got separated from everyone else and spent the afternoon talking. I've wondered ever since whether they remember me.",
      question:
        'Do they remember that afternoon?',
      privateDetails: '',
      createdAt: now(),
      demo: true
    }
  );

  saveDb(db);
}

makeDemoDb();

async function route(req, res) {
  const url = new URL(
    req.url,
    `http://${req.headers.host || 'localhost'}`
  );

  const db = loadDb();
  const user = sessionUser(req, db);
  const method = req.method;

  if (method === 'GET' && url.pathname === '/') {
    return html(res, 'index.html');
  }

  if (method === 'GET' && url.pathname === '/health') {
    return send(res, 200, {
      ok: true,
      service: 'Echo backend',
      time: now()
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/auth/register'
  ) {
    try {
      const b = await readBody(req);

      const name = text(b.name, 40);
      const email = text(b.email, 160).toLowerCase();
      const password = text(b.password, 200);

      if (!name || !email || password.length < 8) {
        return send(res, 400, {
          error:
            'Name, email and a password of at least 8 characters are required.'
        });
      }

      if (!/^\S+@\S+\.\S+$/.test(email)) {
        return send(res, 400, {
          error: 'Enter a valid email address.'
        });
      }

      if (db.users.some(u => u.email === email)) {
        return send(res, 409, {
          error:
            'An account with that email already exists.'
        });
      }

      const { salt, hash } = hashPassword(password);

      const u = {
        id: id(),
        name,
        email,
        salt,
        passwordHash: hash,
        createdAt: now(),
        settings: {
          anonymous: true,
          allowMatching: true,
          visibility: 'archive'
        }
      };

      db.users.push(u);

      const token = id();

      db.sessions.push({
        token,
        userId: u.id,
        expiresAt: new Date(
          Date.now() + 7 * 86400000
        ).toISOString()
      });

      saveDb(db);

      return send(
        res,
        201,
        { user: publicUser(u) },
        { 'Set-Cookie': sessionCookie(token) }
      );
    } catch (e) {
      return send(res, 400, {
        error: e.message
      });
    }
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/auth/login'
  ) {
    try {
      const b = await readBody(req);

      const email = text(
        b.email,
        160
      ).toLowerCase();

      const password = text(b.password, 200);

      const u = db.users.find(
        x => x.email === email
      );

      if (
        !u ||
        !u.salt ||
        !verifyPassword(
          password,
          u.salt,
          u.passwordHash
        )
      ) {
        return send(res, 401, {
          error: 'Invalid email or password.'
        });
      }

      const token = id();

      db.sessions = db.sessions.filter(
        s => s.userId !== u.id
      );

      db.sessions.push({
        token,
        userId: u.id,
        expiresAt: new Date(
          Date.now() + 7 * 86400000
        ).toISOString()
      });

      saveDb(db);

      return send(
        res,
        200,
        { user: publicUser(u) },
        { 'Set-Cookie': sessionCookie(token) }
      );
    } catch (e) {
      return send(res, 400, {
        error: e.message
      });
    }
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/auth/logout'
  ) {
    const token =
      parseCookies(req).echo_session;

    db.sessions = db.sessions.filter(
      s => s.token !== token
    );

    saveDb(db);

    return send(
      res,
      200,
      { ok: true },
      { 'Set-Cookie': clearCookie() }
    );
  }

  if (
    method === 'GET' &&
    url.pathname === '/api/auth/me'
  ) {
    return send(res, 200, {
      user: user ? publicUser(user) : null
    });
  }

  if (
    method === 'GET' &&
    url.pathname === '/api/memories'
  ) {
    const mine =
      url.searchParams.get('mine') === 'true';

    let rows = db.memories.filter(
      m =>
        !m.deleted &&
        (
          mine
            ? user && m.userId === user.id
            : true
        )
    );

    if (!mine) {
      rows = rows.filter(
        m =>
          m.demo ||
          (
            db.users.find(
              u => u.id === m.userId
            )?.settings?.visibility !== 'private'
          )
      );
    }

    rows = rows
      .slice(-50)
      .reverse()
      .map(sanitizeMemory);

    return send(res, 200, {
      memories: rows
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/memories'
  ) {
    if (!user) {
      return send(res, 401, {
        error:
          'Please create an account or log in first.'
      });
    }

    try {
      const b = await readBody(req);

      const m = {
        id: id(),
        userId: user.id,
        name:
          text(b.name, 40) ||
          user.name,
        category: text(b.category, 40),
        year: text(b.year, 20),
        location: text(b.location, 120),
        relationship: text(
          b.relationship,
          80
        ),
        nickname: text(
          b.nickname,
          60
        ),
        title: text(b.title, 120),
        content: text(
          b.content,
          8000
        ),
        question: text(
          b.question,
          500
        ),
        privateDetails: text(
          b.privateDetails,
          2000
        ),
        createdAt: now(),
        demo: false
      };

      if (
        !m.category ||
        !m.title ||
        !m.content
      ) {
        return send(res, 400, {
          error:
            'Category, title and your story are required.'
        });
      }

      db.memories.push(m);

      saveDb(db);

      return send(res, 201, {
        memory: sanitizeMemory(m)
      });
    } catch (e) {
      return send(res, 400, {
        error: e.message
      });
    }
  }

  if (
    method === 'DELETE' &&
    url.pathname.startsWith('/api/memories/')
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const mid =
      url.pathname.split('/').pop();

    const m = db.memories.find(
      x =>
        x.id === mid &&
        x.userId === user.id
    );

    if (!m) {
      return send(res, 404, {
        error: 'Memory not found.'
      });
    }

    m.deleted = true;

    saveDb(db);

    return send(res, 200, {
      ok: true
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/matches'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const b = await readBody(req);

    const source = db.memories.find(
      m =>
        m.id === b.memoryId &&
        m.userId === user.id
    );

    if (!source) {
      return send(res, 404, {
        error: 'Memory not found.'
      });
    }

    const candidates =
      db.memories.filter(
        m =>
          !m.deleted &&
          m.userId !== user.id &&
          (
            m.demo ||
            db.users.find(
              u => u.id === m.userId
            )?.settings?.allowMatching !== false
          )
      );

    function words(s) {
      return new Set(
        text(s, 8000)
          .toLowerCase()
          .split(/[^a-z0-9]+/)
          .filter(w => w.length > 3)
      );
    }

    const sw = words(
      `${source.title} ${source.content} ${source.question}`
    );

    const scored = candidates
      .map(c => {
        let score = 0;
        let reasons = [];

        if (
          source.category &&
          c.category === source.category
        ) {
          score += 25;
          reasons.push('category');
        }

        if (
          source.year &&
          c.year &&
          source.year === c.year
        ) {
          score += 20;
          reasons.push('year');
        }

        if (
          source.location &&
          c.location &&
          source.location.toLowerCase() ===
            c.location.toLowerCase()
        ) {
          score += 20;
          reasons.push('location');
        }

        if (
          source.relationship &&
          c.relationship &&
          source.relationship.toLowerCase() ===
            c.relationship.toLowerCase()
        ) {
          score += 15;
          reasons.push('relationship');
        }

        const overlap = [
          ...sw
        ].filter(w =>
          words(
            `${c.title} ${c.content} ${c.question}`
          ).has(w)
        ).length;

        score += Math.min(
          20,
          overlap * 4
        );

        if (overlap) {
          reasons.push(
            'shared language'
          );
        }

        return {
          memory: c,
          score: Math.min(score, 99),
          reasons
        };
      })
      .sort(
        (a, b) =>
          b.score - a.score
      )[0];

    if (
      !scored ||
      scored.score < 35
    ) {
      return send(res, 200, {
        match: null
      });
    }

    const existing =
      db.matches.find(
        x =>
          (
            x.memoryA === source.id &&
            x.memoryB === scored.memory.id
          ) ||
          (
            x.memoryB === source.id &&
            x.memoryA === scored.memory.id
          )
      );

    const match =
      existing ||
      {
        id: id(),
        memoryA: source.id,
        memoryB: scored.memory.id,
        score: scored.score,
        status: 'verification',
        createdAt: now()
      };

    if (!existing) {
      db.matches.push(match);
      saveDb(db);
    }

    return send(res, 200, {
      match: {
        id: match.id,
        score: match.score,
        status: match.status,
        reasons: scored.reasons
      }
    });
  }

  if (
    method === 'POST' &&
    url.pathname.startsWith('/api/matches/') &&
    url.pathname.endsWith('/verify')
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const mid =
      url.pathname.split('/')[3];

    const match = db.matches.find(
      x => x.id === mid
    );

    if (!match) {
      return send(res, 404, {
        error: 'Match not found.'
      });
    }

    const a = db.memories.find(
      m => m.id === match.memoryA
    );

    const c = db.memories.find(
      m => m.id === match.memoryB
    );

    if (!a || !c) {
      return send(res, 404, {
        error: 'Memory not found.'
      });
    }

    if (
      a.userId !== user.id &&
      c.userId !== user.id
    ) {
      return send(res, 403, {
        error: 'Not your match.'
      });
    }

    const b = await readBody(req);

    const answers = {
      year: text(b.year, 20),
      place: text(b.place, 120),
      shared: text(b.shared, 500),
      detail: text(b.detail, 500),
      relationship: text(
        b.relationship,
        80
      )
    };

    const other =
      a.userId === user.id
        ? c
        : a;

    let score = match.score;

    if (
      answers.year &&
      other.year === answers.year
    ) {
      score += 2;
    }

    if (
      answers.relationship &&
      other.relationship.toLowerCase() ===
        answers.relationship.toLowerCase()
    ) {
      score += 2;
    }

    if (
      answers.place &&
      other.location &&
      answers.place
        .toLowerCase()
        .includes(
          other.location.toLowerCase()
        )
    ) {
      score += 2;
    }

    match.verifications =
      match.verifications || {};

    match.verifications[user.id] = {
      answers,
      submittedAt: now()
    };

    const both =
      (
        match.verifications[a.userId] &&
        match.verifications[c.userId]
      ) ||
      a.demo ||
      c.demo;

    if (both) {
      match.status = 'verified';

      match.score = Math.min(
        99,
        Math.max(
          match.score,
          score
        )
      );
    }

    saveDb(db);

    return send(res, 200, {
      verified: both,
      score: Math.min(99, score),
      status: match.status
    });
  }

  if (
    method === 'POST' &&
    url.pathname.startsWith('/api/matches/') &&
    url.pathname.endsWith('/choice')
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const mid =
      url.pathname.split('/')[3];

    const match = db.matches.find(
      x => x.id === mid
    );

    if (!match) {
      return send(res, 404, {
        error: 'Match not found.'
      });
    }

    const b = await readBody(req);

    const choice = text(
      b.choice,
      60
    );

    if (!choice) {
      return send(res, 400, {
        error: 'Choice required.'
      });
    }

    db.choices.push({
      id: id(),
      matchId: mid,
      userId: user.id,
      choice,
      createdAt: now()
    });

    saveDb(db);

    return send(res, 201, {
      ok: true,
      choice
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/questions'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const b = await readBody(req);

    const matchId = text(
      b.matchId,
      80
    );

    const question = text(
      b.question,
      300
    );

    if (!matchId || !question) {
      return send(res, 400, {
        error:
          'Match and question are required.'
      });
    }

    const match = db.matches.find(
      x => x.id === matchId
    );

    if (!match) {
      return send(res, 404, {
        error: 'Match not found.'
      });
    }

    db.questions.push({
      id: id(),
      matchId,
      userId: user.id,
      question,
      answer: null,
      createdAt: now()
    });

    saveDb(db);

    return send(res, 201, {
      ok: true
    });
  }

  if (
    method === 'GET' &&
    url.pathname === '/api/dashboard'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const mine =
      db.memories.filter(
        m =>
          m.userId === user.id &&
          !m.deleted
      );

    const matches =
      db.matches.filter(m => {
        const a = db.memories.find(
          x => x.id === m.memoryA
        );

        const b = db.memories.find(
          x => x.id === m.memoryB
        );

        return (
          a?.userId === user.id ||
          b?.userId === user.id
        );
      });

    return send(res, 200, {
      user: publicUser(user),

      memories:
        mine.map(sanitizeMemory),

      matches:
        matches.map(m => ({
          id: m.id,
          score: m.score,
          status: m.status
        }))
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/settings'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const b = await readBody(req);

    user.settings = {
      ...user.settings,

      anonymous: !!b.anonymous,

      allowMatching:
        b.allowMatching !== false,

      visibility:
        [
          'archive',
          'matching',
          'private'
        ].includes(b.visibility)
          ? b.visibility
          : user.settings.visibility
    };

    saveDb(db);

    return send(res, 200, {
      settings: user.settings
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/report'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const b = await readBody(req);

    db.reports.push({
      id: id(),
      reporter: user.id,
      targetId: text(
        b.targetId,
        80
      ),
      reason: text(
        b.reason,
        500
      ),
      createdAt: now()
    });

    saveDb(db);

    return send(res, 201, {
      ok: true
    });
  }

  if (
    method === 'POST' &&
    url.pathname === '/api/block'
  ) {
    if (!user) {
      return send(res, 401, {
        error: 'Log in first.'
      });
    }

    const b = await readBody(req);

    db.blocks.push({
      id: id(),
      blocker: user.id,
      targetId: text(
        b.targetId,
        80
      ),
      createdAt: now()
    });

    saveDb(db);

    return send(res, 201, {
      ok: true
    });
  }

  return send(res, 404, {
    error: 'API route not found.'
  });
}

const server = http.createServer(
  (req, res) =>
    route(req, res).catch(err => {
      console.error(err);

      send(res, 500, {
        error: 'Server error.'
      });
    })
);

server.listen(
  PORT,
  () =>
    console.log(
      `Echo running at http://localhost:${PORT}`
    )
);
