const express = require('express');
const http = require('http');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const app = express();

// ===== FASE 2: TRUST PROXY (o Render fica atrás de proxy) =====
app.set('trust proxy', 1);

// ===== FASE 2: HELMET + CSP ESTRITA =====
// script-src 'self' => proíbe JS inline (por isso app.js é arquivo separado)
// connect-src 'self' wss: => permite o WebSocket na mesma origem
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", 'wss:'],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));

app.use(express.json());
app.use(express.static('public'));

const server = http.createServer(app);

// ===== FASE 2: ORIGENS PERMITIDAS (separadas por vírgula na env var) =====
const ORIGENS_PERMITIDAS = (process.env.ORIGENS_PERMITIDAS || 'https://chat-seguro-7nmi.onrender.com,http://localhost:3000')
  .split(',')
  .map(o => o.trim().toLowerCase());

// ===== FASE 2: PAYLOAD MÁXIMO 8 KB POR PACOTE =====
const io = new Server(server, {
  maxHttpBufferSize: 8 * 1024,
  cors: { origin: ORIGENS_PERMITIDAS }
});

// ===== FASE 2: CHECAGEM DE ORIGEM NO HANDSHAKE =====
// CORS sozinho não bloqueia cliente fora do navegador; aqui exigimos o header Origin.

io.use((socket, next) => {
  const origin = socket.handshake.headers.origin;
  // Navegador NÃO envia Origin em GET same-origin (início do polling).
  // Só rejeitamos quando o header VEM e não está na lista (site malicioso de terceiro).
  if (!origin || ORIGENS_PERMITIDAS.includes(origin.toLowerCase())) return next();
  console.log(`[segurança] origem rejeitada: "${origin}"`);
  return next(new Error('origem_negada'));
});

// ===== FASE 2: ESTADO POR CONEXÃO (rate limit de mensagens) =====
io.use((socket, next) => {
  socket.data.ultimaMsg = 0;
  next();
});

// ===== CONSTANTES =====
const MAX_SALAS = 500;
const MAX_MEMBROS = 50;
const TOLERANCIA_PILAR_MS = 20000;
const TOLERANCIA_CONEXAO_MS = 30000;
const INTERVALO_MSG_MS = 500;
const TENTATIVAS_ENTRAR_MAX = 10;
const JANELA_TENTATIVAS_MS = 60000;

// ===== ESTADO EM MEMÓRIA =====
const salas = new Map();

// ===== FASE 2: ANTI-ADIVINHAÇÃO DE CÓDIGO POR IP =====
const tentativasEntrarPorIp = new Map(); // ip -> [timestamps]

function ipDoSocket(socket) {
  const fwd = socket.handshake.headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0].trim() : socket.handshake.address;
}

setInterval(() => {
  const agora = Date.now();
  for (const [ip, ts] of tentativasEntrarPorIp) {
    const recentes = ts.filter(t => agora - t < JANELA_TENTATIVAS_MS);
    if (recentes.length === 0) tentativasEntrarPorIp.delete(ip);
    else tentativasEntrarPorIp.set(ip, recentes);
  }
}, 5 * 60000).unref();

// ===== HELPERS =====
function gerarCodigo() { return crypto.randomBytes(16).toString('base64url'); }
function gerarMemberId() { return crypto.randomBytes(16).toString('hex'); }
function gerarToken() { return crypto.randomBytes(32).toString('hex'); }

const RE_CODIGO = /^[A-Za-z0-9_-]{22}$/;
const RE_TOKEN = /^[a-f0-9]{64}$/;
const RE_CONTROLE = /[\x00-\x1f\x7f]/;

function apelidoValido(a) {
  return typeof a === 'string' && a.length >= 1 && a.length <= 20 && !RE_CONTROLE.test(a);
}
function textoValido(t) {
  return typeof t === 'string' && t.length >= 1 && t.length <= 1000;
}
function listaMembros(sala) {
  const lista = [];
  for (const [memberId, m] of sala.membros) {
    lista.push({ memberId, apelido: m.apelido, pilar: memberId === sala.pilarId });
  }
  return lista;
}

const seguro = (fn) => (...args) => { try { fn(...args); } catch { /* descarta payload malformado */ } };

// ===== DESTRUIÇÃO DE SALA =====
function destruirSala(codigo, motivo) {
  const sala = salas.get(codigo);
  if (!sala) return;
  clearTimeout(sala.timerPilar);
  clearTimeout(sala.timerConexao);
  io.to(codigo).emit('sala_encerrada', { motivo });
  const socketsNaSala = io.sockets.adapter.rooms.get(codigo);
  if (socketsNaSala) {
    for (const socketId of socketsNaSala) {
      const s = io.sockets.sockets.get(socketId);
      if (s) { s.leave(codigo); s.disconnect(true); }
    }
  }
  salas.delete(codigo);
  console.log(`[evento] sala destruída: ${codigo} (${motivo})`);
}

// ===== FASE 2: RATE LIMIT HTTP (criação de salas: 5/min por IP) =====
const criarSalaLimiter = rateLimit({
  windowMs: 60000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { erro: 'Muitas tentativas de criação. Aguarde um minuto.' }
});
app.use('/api/salas', criarSalaLimiter);

// ===== CRIAÇÃO DE SALA VIA HTTP =====
app.post('/api/salas', (req, res) => {
  if (salas.size >= MAX_SALAS) {
    return res.status(503).json({ erro: 'Servidor cheio. Tente mais tarde.' });
  }
  const { apelido, limiteUsos } = req.body || {};
  if (!apelidoValido(apelido)) {
    return res.status(400).json({ erro: 'Apelido inválido (1 a 20 caracteres).' });
  }
  const limite = Number(limiteUsos);
  if (!Number.isInteger(limite) || limite < 2 || limite > 50) {
    return res.status(400).json({ erro: 'limiteUsos deve ser inteiro entre 2 e 50.' });
  }

  const codigo = gerarCodigo();
  const memberId = gerarMemberId();
  const token = gerarToken();
  const agora = Date.now();

  const sala = {
    codigo,
    criadaEm: agora,
    ultimaAtividade: agora,
    limiteUsos: limite,
    usosTotal: 1,
    pilarId: memberId,
    timerPilar: null,
    timerConexao: null,
    membros: new Map([[memberId, { apelido, token, socketId: null }]])
  };
  salas.set(codigo, sala);

  sala.timerConexao = setTimeout(() => {
    const s = salas.get(codigo);
    if (s) {
      const pilar = s.membros.get(memberId);
      if (pilar && !pilar.socketId) destruirSala(codigo, 'Pilar nunca conectou');
    }
  }, TOLERANCIA_CONEXAO_MS);

  console.log(`[evento] sala criada: ${codigo}`);
  res.status(201).json({ codigo, memberId, token });
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  let sessao = null; // { codigo, memberId }

  socket.on('entrar', seguro((payload) => {
    if (sessao) return socket.emit('erro', { motivo: 'Conexão já está em uma sala.' });

    const { codigo, apelido, token } = (payload && typeof payload === 'object') ? payload : {};
    if (typeof codigo !== 'string' || !RE_CODIGO.test(codigo)) {
      return socket.emit('erro', { motivo: 'Código inválido.' });
    }
    if (!apelidoValido(apelido)) {
      return socket.emit('erro', { motivo: 'Apelido inválido (1 a 20 caracteres).' });
    }

    // ===== FASE 2: anti-adivinhação de código por IP =====
    const ip = ipDoSocket(socket);
    const agoraTs = Date.now();
    const recentes = (tentativasEntrarPorIp.get(ip) || []).filter(t => agoraTs - t < JANELA_TENTATIVAS_MS);
    if (recentes.length >= TENTATIVAS_ENTRAR_MAX) {
      return socket.emit('erro', { motivo: 'Muitas tentativas. Aguarde um minuto.' });
    }
    recentes.push(agoraTs);
    tentativasEntrarPorIp.set(ip, recentes);

    const sala = salas.get(codigo);
    if (!sala) return socket.emit('erro', { motivo: 'Sala inexistente ou encerrada.' });

    // --- RECONEXÃO COM TOKEN (não gasta vaga) ---
    if (typeof token === 'string' && RE_TOKEN.test(token)) {
      for (const [mid, membro] of sala.membros) {
        if (membro.token === token) {
          if (membro.socketId) {
            const antigo = io.sockets.sockets.get(membro.socketId);
            if (antigo) antigo.disconnect(true);
          }
          membro.socketId = socket.id;
          membro.apelido = apelido;
          socket.join(codigo);
          sessao = { codigo, memberId: mid };
          sala.ultimaAtividade = Date.now();
          if (mid === sala.pilarId) {
            clearTimeout(sala.timerPilar);
            sala.timerPilar = null;
            clearTimeout(sala.timerConexao);
          }
          socket.emit('entrou', {
            memberId: mid, token: membro.token,
            isPilar: mid === sala.pilarId,
            membros: listaMembros(sala)
          });
          socket.to(codigo).emit('membro_entrou', { memberId: mid, apelido });
          return;
        }
      }
      return socket.emit('erro', { motivo: 'Token inválido para esta sala.' });
    }

    // --- ENTRADA NOVA (gasta 1 uso) ---
    if (sala.usosTotal >= sala.limiteUsos) {
      return socket.emit('erro', { motivo: 'Limite de entradas desta sala atingido.' });
    }
    if (sala.membros.size >= MAX_MEMBROS) {
      return socket.emit('erro', { motivo: 'Sala cheia.' });
    }

    const memberId = gerarMemberId();
    const novoToken = gerarToken();
    sala.usosTotal++;
    sala.membros.set(memberId, { apelido, token: novoToken, socketId: socket.id });
    sala.ultimaAtividade = Date.now();
    socket.join(codigo);
    sessao = { codigo, memberId };

    socket.emit('entrou', {
      memberId, token: novoToken,
      isPilar: false,
      membros: listaMembros(sala)
    });
    socket.to(codigo).emit('membro_entrou', { memberId, apelido });
  }));

  socket.on('enviar_mensagem', seguro((payload) => {
    if (!sessao) return;
    const { texto } = (payload && typeof payload === 'object') ? payload : {};
    if (!textoValido(texto)) return socket.emit('erro', { motivo: 'Mensagem inválida.' });

    // ===== FASE 2: rate limit de mensagens (mínimo 500ms entre envios) =====
    const agora = Date.now();
    if (agora - socket.data.ultimaMsg < INTERVALO_MSG_MS) {
      return socket.emit('erro', { motivo: 'Muito rápido. Aguarde um instante.' });
    }
    socket.data.ultimaMsg = agora;

    const sala = salas.get(sessao.codigo);
    if (!sala) return;
    const membro = sala.membros.get(sessao.memberId);
    if (!membro || membro.socketId !== socket.id) return;

    sala.ultimaAtividade = Date.now();
    io.to(sessao.codigo).emit('mensagem', {
      de: sessao.memberId,
      apelido: membro.apelido,
      texto,
      ts: Date.now()
    });
  }));

  socket.on('expulsar_membro', seguro((payload) => {
    if (!sessao) return;
    const { memberId } = (payload && typeof payload === 'object') ? payload : {};
    const sala = salas.get(sessao.codigo);
    if (!sala) return;
    if (sala.pilarId !== sessao.memberId) {
      return socket.emit('erro', { motivo: 'Somente o Pilar pode expulsar.' });
    }
    if (typeof memberId !== 'string' || memberId === sala.pilarId) {
      return socket.emit('erro', { motivo: 'Alvo inválido.' });
    }
    const alvo = sala.membros.get(memberId);
    if (!alvo) return;

    sala.membros.delete(memberId);
    sala.ultimaAtividade = Date.now();
    if (alvo.socketId) {
      const s = io.sockets.sockets.get(alvo.socketId);
      if (s) {
        s.emit('expulso');
        s.leave(sessao.codigo);
        s.disconnect(true);
      }
    }
    io.to(sessao.codigo).emit('membro_saiu', { memberId, motivo: 'expulso' });
  }));

  socket.on('sair', seguro(() => {
    socket.disconnect(true);
  }));

  socket.on('disconnect', () => {
    if (!sessao) return;
    const sala = salas.get(sessao.codigo);
    if (!sala) return;
    const membro = sala.membros.get(sessao.memberId);
    if (!membro || membro.socketId !== socket.id) return;

    membro.socketId = null;
    sala.ultimaAtividade = Date.now();

    if (sessao.memberId === sala.pilarId) {
      sala.timerPilar = setTimeout(() => {
        const s = salas.get(sessao.codigo);
        if (!s) return;
        const m = s.membros.get(sessao.memberId);
        if (!m || !m.socketId) destruirSala(sessao.codigo, 'O Pilar saiu');
      }, TOLERANCIA_PILAR_MS);
    } else {
      socket.to(sessao.codigo).emit('membro_saiu', { memberId: sessao.memberId, motivo: 'saiu' });
    }
  });
});

const PORTA = process.env.PORT || 3000;
server.listen(PORTA, () => console.log(`✅ Servidor rodando na porta ${PORTA}`));