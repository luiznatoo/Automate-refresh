# Localizador de dispositivos

## Uso

1. Cole os IPs dos switches, um por linha, e escolha o tipo. Também é possível importar CSV.
2. Informe o IP do FortiGate se quiser descoberta automática de IPs e nomes.
3. Informe usuário e senha; clique em Localizar e depois Abrir Excel.

Sem FortiGate, informe a lista no botão MACs opcionais. Em Opções ficam senha diferente para firewall, grupos específicos, tempo de espera, paralelismo, known_hosts, cadastros salvos e detalhes da coleta. A senha permanece somente na sessão.

Uma única tela concentra a coleta. O tipo selecionado é usado para IPs novos; tipos e acessos específicos importados são preservados. CSVs e cadastros antigos continuam aceitos.

## Resultado

O Excel contém somente Dispositivos e Pendências. Dispositivos mostra nome (quando disponível), IP, MAC, switch, porta, VLAN e resultado. Uplinks não são apresentados como localização final. Observações repetidas da mesma porta são consolidadas.

Uma falha em outro equipamento não invalida uma porta identificada. As falhas de consulta aparecem em Pendências; ausência de uma porta não comprova que o dispositivo está desligado. Múltiplas portas de acesso e conflitos de IP/MAC continuam A revisar. Localizado significa uma única porta de acesso observada nesta coleta, sem comprovar conexão física direta nem cobertura total da unidade.

Os registros técnicos ficam na pasta do resultado (JSON e logs) e no botão Detalhes da coleta. Não são acrescentados como abas extensas no Excel. Não é necessário fornecer um modelo Excel.

A coleta é somente leitura. SSH mantém validação de chave do equipamento. Não são descobertos automaticamente endereços ausentes das tabelas consultadas.
