let socket = null;
let eu = null; // { codigo, memberId, token, isPilar, apelido }
let membros = new Map();
let minhasChaves = null;               // par ECDH deste navegador
const chavesDeSala = new Map();        // memberId -> CryptoKey AES-GCM

function mostrar(id) {
  ['telaInicial', 'telaCodigo', 'telaChat'].forEach(t => {
    document.getElementById(t).classList.toggle('hidden', t !== id);
  });
}

async function criarSala() {
  const apelido = document.getElementById('apelidoCriar').value.trim();
  const limiteUsos = Number(document.getElementById('limiteUsos').value);
  const resp = await fetch('/api/salas', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apelido, limiteUsos })
  });
  const dados = await resp.json();
  if (!resp.ok) { alert(dados.erro || 'Erro ao criar sala'); return; }
  eu = { codigo: dados.codigo, memberId: dados.memberId, token: dados.token, isPilar: true, apelido };
  localStorage.setItem('chatseguro:' + dados.codigo, dados.token);
  document.getElementById('codigoGerado').textContent = dados.codigo;
  mostrar('telaCodigo');
}

function copiarCodigo() {
  navigator.clipboard.writeText(eu.codigo).then(() => alert('Código copiado!'));
}

function entrarSala() {
  const codigo = document.getElementById('codigoEntrar').value.trim();
  const apelido = document.getElementById('apelidoEntrar').value.trim();
  conectar(codigo, apelido);
}

function irParaChat() { conectar(eu.codigo, eu.apelido); }

// Quando a chave pública de alguém chega, derivo nosso segredo compartilhado
async function registrarChave(memberId, chavePublicaB64) {
  if (!eu || memberId === eu.memberId || !chavePublicaB64 || !minhasChaves) return;
  try {
    const publicaDeles = await importarPublica(chavePublicaB64);
    chavesDeSala.set(memberId, await derivarChave(minhasChaves, publicaDeles));
  } catch {
    console.warn('chave pública inválida de', memberId);
  }
}

function adicionarMensagem(apelido, texto) {
  const p = document.createElement('p');
  p.textContent = `[${new Date().toLocaleTimeString()}] ${apelido}: ${texto}`;
  document.getElementById('mensagens').appendChild(p);
}

async function conectar(codigo, apelido) {
  if (socket) socket.disconnect();
  chavesDeSala.clear();
  minhasChaves = await gerarParDeChaves();      // 1. gera minhas chaves
  const chavePublica = await exportarPublica(minhasChaves);
  socket = io();
  const token = localStorage.getItem('chatseguro:' + codigo) || undefined;

  socket.on('connect', () => {
    socket.emit('entrar', { codigo, apelido, token, chavePublica }); // 2. publica a chave
  });

  socket.on('entrou', (dados) => {
    eu = { codigo, memberId: dados.memberId, token: dados.token, isPilar: dados.isPilar, apelido };
    localStorage.setItem('chatseguro:' + codigo, dados.token);
    membros = new Map(dados.membros.map(m => [m.memberId, m]));
    renderizarMembros();
    mostrar('telaChat');
    for (const m of dados.membros) registrarChave(m.memberId, m.chavePublica); // 3. deriva com quem já tá lá
  });

  socket.on('mensagem', async (m) => {
    if (eu && m.de === eu.memberId) return; // minha mensagem já foi exibida localmente
    const item = (m.cifrados || []).find(c => eu && c.para === eu.memberId);
    if (!item || !chavesDeSala.has(m.de)) {
      return adicionarMensagem(m.apelido, '[mensagem cifrada]');
    }
    try {
      const texto = await descriptografar(chavesDeSala.get(m.de), item.iv, item.ct); // 5. decifra
      adicionarMensagem(m.apelido, texto);
    } catch {
      adicionarMensagem(m.apelido, '[não foi possível decifrar]');
    }
  });

  socket.on('membro_entrou', (m) => {
    membros.set(m.memberId, { apelido: m.apelido });
    renderizarMembros();
    registrarChave(m.memberId, m.chavePublica);
  });
  socket.on('chave_publica', (m) => registrarChave(m.memberId, m.chavePublica));
  socket.on('membro_saiu', (m) => {
    membros.delete(m.memberId);
    chavesDeSala.delete(m.memberId);
    renderizarMembros();
  });

  socket.on('expulso', () => { alert('Você foi expulso da sala.'); sairLimpo(); });
  socket.on('sala_encerrada', (d) => { alert('Sala encerrada: ' + (d && d.motivo ? d.motivo : 'fim')); sairLimpo(); });
  socket.on('erro', (e) => alert((e && e.motivo) || 'Erro.'));
  socket.on('connect_error', (e) => alert('Falha na conexão: ' + e.message));
}

async function enviar() {
  const campo = document.getElementById('texto');
  if (!socket || campo.value.trim() === '') return;
  const texto = campo.value;
  if (chavesDeSala.size === 0) {
    alert('Você está sozinho na sala. Aguarde outra pessoa entrar.');
    return;
  }
  // 4. cifra uma cópia para CADA pessoa da sala
  const cifrados = [];
  for (const [memberId, chave] of chavesDeSala) {
    cifrados.push({ para: memberId, ...(await criptografar(chave, texto)) });
  }
  socket.emit('enviar_mensagem', { cifrados });
  adicionarMensagem(eu.apelido, texto);
  campo.value = '';
}

function renderizarMembros() {
  const ul = document.getElementById('listaMembros');
  ul.textContent = '';
  for (const [id, m] of membros) {
    const li = document.createElement('li');
    let rotulo = m.apelido;
    if (m.pilar) rotulo += ' 👑';
    if (eu && id === eu.memberId) rotulo += ' (você)';
    li.textContent = rotulo;
    if (eu && eu.isPilar && id !== eu.memberId) {
      const btn = document.createElement('button');
      btn.textContent = 'Expulsar';
      btn.addEventListener('click', () => socket.emit('expulsar_membro', { memberId: id }));
      li.appendChild(document.createTextNode(' '));
      li.appendChild(btn);
    }
    ul.appendChild(li);
  }
}

function sairLimpo() {
  if (socket) { socket.disconnect(); socket = null; }
  eu = null;
  membros = new Map();
  chavesDeSala.clear();
  minhasChaves = null;
  mostrar('telaInicial');
}

// ===== Ligação dos botões =====
document.getElementById('btnCriar').addEventListener('click', criarSala);
document.getElementById('btnEntrar').addEventListener('click', entrarSala);
document.getElementById('btnCopiar').addEventListener('click', copiarCodigo);
document.getElementById('btnIrChat').addEventListener('click', irParaChat);
document.getElementById('btnEnviar').addEventListener('click', enviar);
document.getElementById('btnSair').addEventListener('click', sairLimpo);
document.getElementById('texto').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') enviar();
});