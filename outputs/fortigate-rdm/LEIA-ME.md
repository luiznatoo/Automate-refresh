# FortiGate — pré e pós-RDM

## Modelo padrão do comparador

O Excel gerado pelo menu e pelo comando `comparar` usa automaticamente **modelo_comparativo.xlsx**, baseado no arquivo Comparativo_FortiGate_RDM fornecido. Mantenha esse arquivo junto dos três scripts Python.

As primeiras abas são **Comparativo** e **Evidencias**, com o layout, fórmulas, listas de validação e cores do modelo. As linhas são ampliadas automaticamente, além dos 50 itens/200 evidências originais. Cada item identifica equipamento, categoria e objeto; logs pré/pós são vinculados por ID. Logs longos são divididos em partes. Se o TXT não estiver disponível, a evidência identifica expressamente que contém dados estruturados do snapshot.

**Alertas, Cobertura e Hosts** permanecem como abas de apoio dentro desse mesmo arquivo. Resultado esperado, validação técnica, responsável e parecer final continuam sob avaliação humana. Itens sem coleta ficam pendentes, sem aprovação automática. Fórmulas são recalculadas pelo Excel ao abrir o arquivo.

Você não precisa preencher caminhos do modelo nem mudar o fluxo do menu. Para aplicar o modelo a coletas antigas, escolha **3 — Comparar coletas já salvas**. Os logs, snapshots e relatórios antigos não são modificados.

## Modo simples: menu interativo

Execute `fortigate_rdm.py` sem argumentos, inclusive pelo botão Executar do VS Code. Aparecem as opções:

1. **Coletar PRÉ-RDM:** informe o número da RDM e as credenciais.
2. **Coletar PÓS-RDM e gerar Excel:** escolha o pré salvo pelo número na lista e informe as credenciais. O pós e a comparação são feitos em sequência, sem copiar caminhos.
3. **Comparar coletas já salvas:** escolha o pré e o pós nas listas. Funciona offline.
0. **Sair.**

Pode fechar o programa entre o pré e o pós. Coletas salvas permanecem disponíveis. A lista mostra horário UTC, equipamentos e áreas interpretadas. Coletas totalmente falhas não são oferecidas; coletas parciais são identificadas. O pós automático confere se nomes, endereços e portas do inventário correspondem ao pré escolhido. Senhas continuam sendo solicitadas e não são salvas.

```powershell
python .\fortigate_rdm.py
```

Os comandos com argumentos descritos abaixo continuam funcionando para uso avançado.

Automação independente da ferramenta de switches. Destinada a FortiOS **7.4.9 e 7.4.12**, com **HA e VDOM desabilitado**, via SSH. Coleta consultas de estado, salva logs e gera comparação Excel. Ainda requer validação nos seus modelos/versões reais: os testes entregues foram locais, com saídas representativas e SSH simulado.

## Arquivos necessários

- `fortigate_rdm.py`: execução, SSH e logs.
- `parsers.py`: interpretação das respostas.
- `comparar.py`: comparação e Excel.
- `inventario.csv`: lista de clusters/equipamentos.
- `requirements.txt`: instalação das dependências.

Depende de `modelo_comparativo.xlsx`, incluído no pacote, mas não de arquivos da automação dos switches. Os testes de desenvolvimento ficam fora do pacote de uso diário.

## Instalar

Abra PowerShell na pasta extraída:

```powershell
python -m pip install -r .\requirements.txt
```

Use esse mesmo Python para executar. Alternativamente, crie um ambiente virtual com Python 3.10+ e instale requirements.txt nele.

## Inventário

```csv
nome,host,porta,usuario,password_env,key_file
FGT-MATRIZ,192.0.2.10,22,,FGT_PASSWORD,
FGT-FILIAL,192.0.2.20,22,,FGT_PASSWORD,
```

Substitua os endereços de documentação por endereços reais. `nome` deve ser único e permanecer igual no pré/pós. Para HA, use **uma entrada por cluster**, no endereço de gerenciamento pelo qual você acessa o membro ativo. Mantenha o mesmo endereço nas duas fases, inclusive se houver troca do membro primário. A saúde/participação dos membros é obtida do cluster; a ferramenta não abre sessões independentes no secundário nem provoca failover.

`usuario` pode ser preenchido por linha; vazio solicita usuário compartilhado. `password_env` é o nome de uma variável, não a senha; por padrão FGT_PASSWORD. Se não estiver definida, a senha é solicitada de forma oculta. Use nomes diferentes para senhas distintas. `key_file` opcional aponta para chave privada sem passphrase; caminhos relativos são resolvidos a partir do inventário. Não há suporte interativo a MFA/OTP ou disclaimer de login.

A chave SSH deve estar no `known_hosts`, como na ferramenta dos switches. Para um equipamento novo, faça primeiro `ssh usuario@IP`, confira a impressão digital e aceite apenas a chave esperada. `--known-hosts caminho` permite usar um arquivo específico.

## 1. Coletar antes da RDM

```powershell
python .\fortigate_rdm.py coletar --fase pre --rdm RDM12345
```

O terminal informa o caminho exato do `snapshot.json`. Cada execução cria uma pasta exclusiva em `coletas/RDM12345/pre_DATA_HORA/`, com JSON estruturado e logs de cada comando em arquivos TXT. O nome das subpastas de equipamento é um identificador; o cabeçalho de cada log contém nome, horário UTC e comando.

**Confira a coleta pré antes de iniciar a mudança.** Saída com áreas a revisar significa comando recusado, falha SSH ou formato não interpretado. Um pré incompleto limita a comparação posterior. Logs são consultas pontuais do estado; não são exportação contínua de eventos do firewall.

## 2. Coletar após a RDM

Após aguardar a estabilização/convergência prevista para a mudança:

```powershell
python .\fortigate_rdm.py coletar --fase pos --rdm RDM12345
```

Pode repetir o pós quantas vezes precisar, sempre preservando execuções anteriores. Não há espera automática de convergência ou decisão automática de aprovação da RDM.

## 3. Comparar e gerar Excel

Use os caminhos reais exibidos nas duas execuções (substitua DATA_HORA):

```powershell
python .\fortigate_rdm.py comparar --pre ".\coletas\RDM12345\pre_DATA_HORA\snapshot.json" --pos ".\coletas\RDM12345\pos_DATA_HORA\snapshot.json"
```

A comparação funciona offline e salva um Excel em `relatorios/`. Opcional: `--saida caminho.xlsx`. Um destino existente é recusado para preservar relatórios anteriores.

## Conteúdo da comparação

| Área | Dados e verificações |
|---|---|
| BGP | Vizinhos por VRF, estado, ASN, prefixos recebidos; sessão perdida ou redução de prefixos |
| VPN IPsec | Túnel/peer, quantidade total e ativa de seletores; redução dos ativos |
| Rotas IPv4 | Prefixo por VRF, protocolo, próximo salto e interface; preserva múltiplos caminhos ECMP |
| Interfaces | Estado administrativo/link, interfaces/VLANs configuradas, IPs e relação com interface pai |
| ARP IPv4 | IP, MAC e interface; ausentes, novos e MAC/interface alterados |
| DHCP local | Leases IPv4, MAC, interface quando fornecida e detalhes; configurações de escopos e reservas |
| HA | Saúde, membros, primário/secundário e sincronismo quando presentes na saída |
| SD-WAN | Estado alive/dead dos membros por health-check |
| Recursos/sistema | Versão, serial, hostname, uptime, memória e CPU reportados; alterações informativas |

Abas principais: **Resumo**, **Alertas**, **Cobertura** e **Hosts**. Abas complementares mostram os dados pré/pós de cada área. Os TXT permitem conferir saídas originais e formatos não reconhecidos. Prioridade Alta inclui falhas de coleta: leia o Evento para distinguir indisponibilidade de dados de perda de serviço.

Os dados coletados dos equipamentos são gravados como texto quando textuais, mesmo se começarem com `=`, evitando interpretar descrições como fórmulas do Excel. Senhas fornecidas ao coletor e campos sensíveis reconhecidos são ocultados nos logs; os relatórios ainda contêm endereços, MACs e informações internas da rede.

## Interpretação dos hosts

- **Não observado no pós:** o IP existia naquela fonte no pré e não aparece agora. Não significa automaticamente desligado; ARP expira e leases mudam.
- **MAC ou interface alterado:** possível mudança de host, VLAN, endereço ou substituição de equipamento.
- **Mesmo MAC com IP/interface diferente:** ajuda a localizar equipamento que mudou de endereço. MAC aleatório, compartilhado ou proxy ARP limita essa associação.
- **VLAN da interface alterada:** relação VLAN/interface mudou nas configurações coletadas.
- **Comparação inconclusiva:** uma fase falhou ou o formato não foi reconhecido. Não são emitidas remoções em massa nessa área.

ARP e DHCP são comparados separadamente. Um IP ausente em ARP pode ter lease DHCP ainda válido, sem estar ativo. Apenas hosts diretamente observáveis no FortiGate aparecem; equipamentos atrás de outro roteador ou sem tráfego recente podem não estar presentes. O DHCP só cobre o servidor local do FortiGate; servidor DHCP externo/relay requer coleta adicional nesse servidor.

Esta versão não realiza ping, varredura ou testes de aplicações. Não altera configuração, não limpa ARP/leases/sessões e não reinicia túneis. Usa um shell SSH que trata paginação, sem desabilitá-la por alteração da configuração do FortiGate.

## Limites técnicos

- Cobertura de hosts e rotas é IPv4. NDP/rotas IPv6, SSL VPN, FortiSwitch/FortiAP, políticas/NAT, logs de tráfego, rotas BGP anunciadas por vizinho e testes de aplicações não são cobertos automaticamente nesta versão.
- VPN compara contagem de seletores ativos por túnel/peer; não identifica individualmente cada seletor nem testa tráfego útil. Túneis sob demanda podem cair por inatividade sem falha de serviço.
- O momento da coleta é por comando; não é um snapshot atômico do cluster. Failover durante uma coleta pode interromper SSH; repita a fase após estabilização.
- Troca de primário/serial pode ser esperada durante manutenção. Inventário estável identifica o cluster; alterações são exibidas para revisão.
- Campos/formatos variam conforme modelo, build e recursos habilitados. Formatos não reconhecidos ficam inconclusivos; o log é preservado para ajuste do parser.
- Valores de CPU/memória são comparados como informação, sem limiar fixo de alarme. Contadores de erros VPN ficam nas abas de dados; não são classificados por delta, pois reinicializações zeram contadores.

## Opções e retorno

Coleta: `--workers 3`, `--timeout 120`, `--usuario`, `--inventario`, `--known-hosts`, `--nao-interativo`. No modo não interativo, forneça FGT_USER/FGT_PASSWORD ou equivalentes do inventário. Timeout máximo por comando; falha de transporte interrompe aquele equipamento para evitar interpretar uma saída de comando como outra.

Código de saída: 0 = coleta/comparação processada sem áreas inconclusivas (não significa ausência de impacto); 2 = coleta parcial/falha ou comparação incompleta; 1 = erro de entrada/dependência/arquivo. O Excel deve ser interpretado junto com Alertas e Cobertura.

## Referências de comandos

- https://docs.fortinet.com/document/fortigate/7.4.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet
- https://docs.fortinet.com/document/fortigate/7.4.9/administration-guide/509828/vrf-routing-support
- https://community.fortinet.com/fortigate-3/technical-tip-dhcp-address-leases-on-a-fortigate-97322
