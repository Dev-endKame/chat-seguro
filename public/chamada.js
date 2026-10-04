// ===== CHAMADAS EM GRUPO + TELA (WebRTC) =====
// A mídia vai direto entre navegadores (P2P, criptografada pelo próprio WebRTC).
// O servidor só repassa sinais (offer/answer/ICE) — fica cego igual às mensagens.

let naChamada = false;
let midiaLocal = null;   // microfone
let telaLocal = null;    // tela compartilhada
const pares = new Map(); // memberId -> { pc, fazendoOferta, ignorarOferta, educado }

const CONFIG_RTC = {
  iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
};

function apelidoDe(memberId) {
  const m = membros.get(memberId);
  return m ? m.apelido : memberId;
}

function sinal(para, obj) {
  socket.emit('chamada_sinal', { para, dados: JSON.stringify(obj) });
}

// ----- Conexão com UMA pessoa -----
function criarPar(memberId) {
  if (pares.has(memberId)) return pares.get(memberId);
  const pc = new RTCPeerConnection(CONFIG_RTC);
  const par = {
    pc,
    fazendoOferta: false,
    ignorarOferta: false,
    educado: eu.memberId > memberId // regra fixa: em colisão, o "menor" id cede
  };
  pares.set(memberId, par);

  // joga minha mídia local dentro da conexão
  if (midiaLocal) midiaLocal.getTracks().forEach(t => pc.addTrack(t, midiaLocal));
  if (telaLocal) telaLocal.getTracks().forEach(t => pc.addTrack(t, telaLocal));

  pc.onicecandidate = ({ candidate }) => sinal(memberId, { candidate });
  pc.ontrack = (event) => anexarMidiaRemota(memberId, event.streams[0]);
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      encerrarPar(memberId);
    }
  };
  pc.onnegotiationneeded = async () => {
    try {
      par.fazendoOferta = true;
      await pc.setLocalDescription();
      sinal(memberId, { description: pc.localDescription });
    } catch (e) {
      console.error(e);
    } finally {
      par.fazendoOferta = false;
    }
  };
  return par;
}

function encerrarPar(memberId) {
  const par = pares.get(memberId);
  if (!par) return;
  try { par.pc.close(); } catch (e) {}
  pares.delete(memberId);
  const box = document.getElementById('videobox-' + memberId);
  if (box) box.remove();
  atualizarChamadaUI();
}

function anexarMidiaRemota(memberId, stream) {
  let box = document.getElementById('videobox-' + memberId);
  if (!box) {
    box = document.createElement('div');
    box.id = 'videobox-' + memberId;
    box.className = 'videobox';
    const rotulo = document.createElement('span');
    rotulo.textContent = apelidoDe(memberId);
    box.appendChild(rotulo);
    const v = document.createElement('video');
    v.id = 'video-' + memberId;
    v.autoplay = true;
    v.playsInline = true;
    v.controls = true; // player visível: garante áudio em celular e permite ajustar volume
    // clique duplo = tela cheia (com fallback pro Safari/iOS)
    v.addEventListener('dblclick', () => {
      if (v.requestFullscreen) v.requestFullscreen();
      else if (v.webkitEnterFullscreen) v.webkitEnterFullscreen();
    });
    box.appendChild(v);
    document.getElementById('videos').appendChild(box);
  }
  const v = document.getElementById('video-' + memberId);
  v.srcObject = stream;
  v.play().catch(() => {}); // destrava autoplay em navegadores de celular
}

// ----- Sinalização (padrão "perfect negotiation", anti-colisão) -----
async function tratarSinal(de, dadosBrutos) {
  if (!naChamada) return;
  let par = pares.get(de);
  if (!par) par = criarPar(de);
  const { pc } = par;
  try {
    const mensagem = JSON.parse(dadosBrutos);
    if (mensagem.description) {
      const colisao =
        mensagem.description.type === 'offer' &&
        (par.fazendoOferta || pc.signalingState !== 'stable');
      par.ignorarOferta = !par.educado && colisao;
      if (par.ignorarOferta) return;
      await pc.setRemoteDescription(mensagem.description);
      if (mensagem.description.type === 'offer') {
        await pc.setLocalDescription();
        sinal(de, { description: pc.localDescription });
      }
    } else if (mensagem.candidate) {
      try {
        await pc.addIceCandidate(mensagem.candidate);
      } catch (e) {
        if (!par.ignorarOferta) throw e;
      }
    }
  } catch (e) {
    console.error('sinal falhou:', e);
  }
}

// ----- Entrar/sair -----
async function entrarNaChamada() {
  if (naChamada) return;
  try {
    midiaLocal = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch {
    alert('Não consegui acessar o microfone. Verifique a permissão no navegador.');
    return;
  }
  naChamada = true;
  document.getElementById('chamadaAviso').classList.add('hidden');
  socket.emit('chamada_entrar');
  atualizarChamadaUI();
}

async function iniciarChamada() {
  if (naChamada) return;
  await entrarNaChamada();
  if (naChamada) socket.emit('chamada_iniciar', { comVideo: false });
}

function entrarComParticipantes(ids) {
  for (const id of ids) criarPar(id); // cada par dispara sua oferta sozinho
  atualizarChamadaUI();
}

function novoParticipante(memberId) {
  if (!naChamada) return;
  criarPar(memberId); // quem já está na chamada conecta com o novato
}

function desligarChamada() {
  if (!naChamada) return;
  socket.emit('chamada_sair');
  pararTudoLocal();
}

function pararTudoLocal() {
  for (const id of [...pares.keys()]) encerrarPar(id);
  pararTela();
  if (midiaLocal) {
    midiaLocal.getTracks().forEach(t => t.stop());
    midiaLocal = null;
  }
  naChamada = false;
  document.getElementById('chamadaAviso').classList.add('hidden');
  atualizarChamadaUI();
}

// ----- Compartilhamento de tela -----
async function compartilharTela() {
  if (!naChamada) await entrarNaChamada();
  if (!naChamada) return;
  if (telaLocal) { pararTela(); return; } // clicar de novo para de compartilhar
  try {
    telaLocal = await navigator.mediaDevices.getDisplayMedia({ video: true });
  } catch {
    return; // usuário cancelou a escolha da tela
  }
  const trilha = telaLocal.getVideoTracks()[0];
  trilha.onended = () => pararTela(); // usuário clicou em "Parar" na barra do navegador
  for (const { pc } of pares.values()) pc.addTrack(trilha, telaLocal); // renegocia sozinho
  atualizarChamadaUI();
}

function pararTela() {
  if (!telaLocal) return;
  const trilha = telaLocal.getVideoTracks()[0];
  for (const { pc } of pares.values()) {
    const sender = pc.getSenders().find(s => s.track === trilha);
    if (sender) pc.removeTrack(sender);
  }
  trilha.stop();
  telaLocal = null;
  atualizarChamadaUI();
}

// ----- Interface -----
function mostrarAvisoChamada(d) {
  if (naChamada) return;
  document.getElementById('chamadaQuem').textContent = d.apelido;
  document.getElementById('chamadaAviso').classList.remove('hidden');
}

function atualizarChamadaUI() {
  document.getElementById('chamadaBarra').classList.toggle('hidden', !naChamada);
  document.getElementById('contagemChamada').textContent = naChamada ? pares.size + 1 : 0;
  const btnTela = document.getElementById('btnCompartilhar');
  if (btnTela) btnTela.textContent = telaLocal ? '⏹ Parar tela' : '🖥️ Compartilhar tela';
}

// ===== Ligação dos botões =====
document.getElementById('btnLigar').addEventListener('click', iniciarChamada);
document.getElementById('btnEntrarChamada').addEventListener('click', entrarNaChamada);
document.getElementById('btnCompartilhar').addEventListener('click', compartilharTela);
document.getElementById('btnDesligar').addEventListener('click', desligarChamada);