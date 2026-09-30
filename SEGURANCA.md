# Modelo de Ameaça — Chat Seguro Efêmero

## Quem é o atacante

1. **Membro hostil** — alguém dentro da sala que tenta injetar script (XSS),
   floodar mensagens, adivinhar códigos de outras salas ou fingir ser outra pessoa.
2. **Atacante de rede** — alguém no mesmo Wi-Fi/ISP inspecionando ou alterando
   tráfego (MITM).
3. **Bots** — automações tentando criar salas em massa ou forçar códigos.
4. **Operador curioso** — quem roda o servidor e quer ler o conteúdo das conversas.

## Fora de escopo (limites honestos do sistema)

- **Servidor que entrega JavaScript malicioso**: o servidor entrega o código do
  cliente; um servidor comprometido poderia servir JS que rouba chaves. Mitigação
  parcial: código aberto, mas quem não audita o que roda confia no operador.
- **Aparelho comprometido**: se o celular/PC do usuário tem malware, nenhuma
  criptografia no trânsito ajuda.
- **Análise de metadados**: mesmo com E2EE, o servidor vê quem fala com quem,
  quando, tamanho das mensagens e IPs. O conteúdo fica oculto; o padrão de
  comunicação, não.

## O que cada fase resolve

| Fase | Ameaça que resolve |
|---|---|
| Fase 1 (validação, entropia, teto de salas) | Bots, adivinhação de código, estouro de RAM |
| Fase 2 (helmet, CSP, rate limit, origin, textContent) | XSS, flood, abuso por IP |
| Fase 3 (expiração, HTTPS/WSS) | Salas zumbis, inspeção de tráfego em rede |
| Fase 4 (E2EE: ECDH+HKDF+AES-GCM, épocas, anti-replay) | Operador curioso, MITM no conteúdo |

## Regra de ouro de logs

Nunca logar conteúdo de mensagens. Apenas eventos: sala criada, sala destruída,
membro entrou/saiu.
