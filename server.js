const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Diz pro Express servir os arquivos da pasta "public" pro navegador
app.use(express.static('public'));

// ===== A LÓGICA DO CHAT =====

io.on('connection', (socket) => {
  console.log('Alguém conectou:', socket.id);

  // Quando alguém entra com um código
  socket.on('entrar', (codigo) => {
    socket.join(codigo);          // entra na sala (cria se não existir!)
    socket.salaAtual = codigo;    // guarda pra usar depois
    console.log(`Usuário entrou na sala ${codigo}`);
    socket.to(codigo).emit('aviso', 'Uma pessoa entrou na sala');
  });

  // Quando alguém envia uma mensagem
  socket.on('mensagem', (texto) => {
    io.to(socket.salaAtual).emit('mensagem', texto); // manda pra TODOS da sala
  });

  // Quando alguém desconecta
  socket.on('disconnect', () => {
    console.log('Alguém saiu:', socket.id);
  });
});

const PORTA = process.env.PORT || 3000;
server.listen(PORTA, () => {
  console.log(`✅ Servidor rodando na porta ${PORTA}`);
});