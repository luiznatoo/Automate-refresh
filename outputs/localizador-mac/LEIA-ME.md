# Localizador de dispositivos

## Uso

1. Clique em Adicionar switch e informe hostname, IP/DNS e tipo (Juniper ou Cisco). Também é possível importar CSV.
2. Clique em Adicionar firewall e informe hostname e IP/DNS do FortiGate para descoberta automática.
3. Informe usuário e senha; clique em Localizar e depois Abrir Excel.

Sem FortiGate, informe a lista no botão MACs opcionais. Em Opções ficam senha diferente para firewall, grupos específicos, tempo de espera, paralelismo, known_hosts, cadastros salvos e detalhes da coleta. A senha permanece somente na sessão.

Uma única tela concentra a coleta. A lista mostra tipo, hostname e IP/DNS. Editar e Remover funcionam sobre os itens selecionados. Acessos específicos importados são preservados. CSVs e cadastros antigos continuam aceitos.

## Resultado

O Excel contém somente Dispositivos e Pendências. Dispositivos mostra nome (quando disponível), IP, MAC, switch, porta, VLAN e resultado. Uplinks não são apresentados como localização final. Observações repetidas da mesma porta são consolidadas.

Uma falha em outro equipamento não invalida uma porta identificada. As falhas de consulta aparecem em Pendências; ausência de uma porta não comprova que o dispositivo está desligado. Múltiplas portas de acesso e conflitos de IP/MAC continuam A revisar. Localizado significa uma única porta de acesso observada nesta coleta, sem comprovar conexão física direta nem cobertura total da unidade.

Os registros técnicos ficam na pasta do resultado (JSON e logs) e no botão Detalhes da coleta. Não são acrescentados como abas extensas no Excel. Não é necessário fornecer um modelo Excel.

A coleta é somente leitura. SSH mantém validação de chave do equipamento. Não são descobertos automaticamente endereços ausentes das tabelas consultadas.
