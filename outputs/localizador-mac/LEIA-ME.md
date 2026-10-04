# Localizador de dispositivos

## Uso

1. Em Equipamentos, cadastre IP e plataforma dos switches ou importe CSV. Nome é opcional; vazio utiliza o IP.
2. Cadastre o FortiGate para descobrir dispositivos por ARP/DHCP. Sem FortiGate, informe os MACs na aba MACs opcionais.
3. Informe usuário e senha SSH uma vez. Por padrão a senha é compartilhada; desmarque a opção se o firewall usar outra senha.
4. Clique em Iniciar coleta e depois Abrir Excel.

Acesso específico por equipamento e Opções mantêm porta, grupos de senha, arquivo known_hosts, timeout e paralelismo para situações que precisam desses ajustes. Os projetos antigos continuam aceitos. Credenciais ficam somente na sessão.

## Resultado

O Excel contém somente Dispositivos e Pendências. Dispositivos mostra nome (quando disponível), IP, MAC, switch, porta, VLAN e resultado. Uplinks não são apresentados como localização final. Observações repetidas da mesma porta são consolidadas.

Uma falha em outro equipamento não invalida uma porta identificada. As falhas de consulta aparecem em Pendências; ausência de uma porta não comprova que o dispositivo está desligado. Múltiplas portas de acesso e conflitos de IP/MAC continuam A revisar. Localizado significa uma única porta de acesso observada nesta coleta, sem comprovar conexão física direta nem cobertura total da unidade.

Os registros técnicos ficam na pasta do resultado (JSON e logs) e no botão Detalhes da coleta. Não são acrescentados como abas extensas no Excel. Não é necessário fornecer um modelo Excel.

A coleta é somente leitura. SSH mantém validação de chave do equipamento. Não são descobertos automaticamente endereços ausentes das tabelas consultadas.
