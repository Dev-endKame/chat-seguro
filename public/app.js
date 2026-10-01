let socket = null;
let eu = null; // { codigo, memberId, token, isPilar, apelido }
let membros = new Map();

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

function conectar(codigo, apelido) {
  if (socket) socket.disconnect();
  socket = io();
  const token = localStorage.getItem('chatseguro:' + codigo) || undefined;

  socket.on('connect', () => {
    socket.emit('entrar', { codigo, apelido, token });
  });

  socket.on('entrou', (dados) => {
    eu = { codigo, memberId: dados.memberId, token: dados.token, isPilar: dados.isPilar, apelido };
    localStorage.setItem('chatseguro:' + codigo, dados.token);
    membros = new Map(dados.membros.map(m => [m.memberId, m]));
    renderizarMembros();
    mostrar('telaChat');
  });

  socket.on('mensagem', (m) => {
    const p = document.createElement('p');
    const hora = new Date(m.ts).toLocaleTimeString();
    p.textContent = `[${hora}] ${m.apelido}: ${m.texto}`;
    document.getElementById('mensagens').appendChild(p);
  });

  socket.on('membro_entrou', (m) => { membros.set(m.memberId, { apelido: m.apelido }); renderizarMembros(); });
  socket.on('membro_saiu', (m) => { membros.delete(m.memberId); renderizarMembros(); });

  socket.on('expulso', () => { alert('Você foi expulso da sala.'); sairLimpo(); });
  socket.on('sala_encerrada', (d) => { alert('Sala encerrada: ' + (d && d.motivo ? d.motivo : 'fim')); sairLimpo(); });
  socket.on('erro', (e) => alert((e && e.motivo) || 'Erro.'));
  socket.on('connect_error', (e) => alert('Falha na conexão: ' + e.message));
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

function enviar() {
  const campo = document.getElementById('texto');
  if (!socket || campo.value.trim() === '') return;
  socket.emit('enviar_mensagem', { texto: campo.value });
  campo.value = '';
}

function sairLimpo() {
  if (socket) { socket.disconnect(); socket = null; }
  eu = null;
  membros = new Map();
  mostrar('telaInicial');
}

// ===== Ligação dos botões (obrigatório: CSP proíbe onclick inline) =====
document.getElementById('btnCriar').addEventListener('click', criarSala);
document.getElementById('btnEntrar').addEventListener('click', entrarSala);
document.getElementById('btnCopiar').addEventListener('click', copiarCodigo);
document.getElementById('btnIrChat').addEventListener('click', irParaChat);
document.getElementById('btnEnviar').addEventListener('click', enviar);
document.getElementById('btnSair').addEventListener('click', sairLimpo);
document.getElementById('texto').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') enviar();
});