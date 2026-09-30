const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const server = http.createServer(app);
const io = new Server(server);

// ===== CONSTANTES (limites do roadmap v2) =====
const MAX_SALAS = 500;
const MAX_MEMBROS = 50;
const TOLERANCIA_PILAR_MS = 20000;      // 20s de tolerância se o Pilar cair
const TOLERANCIA_CONEXAO_MS = 30000;    // 30s pro Pilar conectar o socket após criar

// ===== ESTADO EM MEMÓRIA (zero banco de dados) =====
const salas = new Map(); // codigo -> sala

// sala = {
//   codigo, criadaEm, ultimaAtividade,
//   limiteUsos, usosTotal, pilarId,
//   timerPilar: null, timerConexao: null,
//   membros: Map(memberId -> { apelido, token, socketId|null })
// }

// ===== HELPERS =====
function gerarCodigo() {
  return crypto.randomBytes(16).toString('base64url'); // 128 bits, 22 caracteres
}
function gerarMemberId() {
  return crypto.randomBytes(16).toString('hex'); // 32 hex
}
function gerarToken() {
  return crypto.randomBytes(32).toString('hex'); // 64 hex
}

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

// Wrapper: qualquer payload malformado é descartado SEM crashar o servidor
const seguro = (fn) => (...args) => { try { fn(...args); } catch { /* descarta */ } };

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

// ===== FASE 1: CRIAÇÃO DE SALA VIA HTTP =====
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

  // Se o Pilar não conectar pelo socket em 30s, a sala morre
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

// ===== SOCKET.IO: ENTRAR, MENSAGEM, EXPULSAR, SAIR =====
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

    const sala = salas.get(sessao.codigo);
    if (!sala) return;
    const membro = sala.membros.get(sessao.memberId);
    if (!membro || membro.socketId !== socket.id) return; // só repassa se o socket pertence à sala

    sala.ultimaAtividade = Date.now();
    // O SERVIDOR monta a identidade: nunca confia no que o cliente diz sobre quem ele é
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
    socket.disconnect(true); // o handler de disconnect cuida do resto
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
      // Pilar caiu: tolerância de 20s pra ele voltar com o token
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