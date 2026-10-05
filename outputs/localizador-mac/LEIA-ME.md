# Mapeamento de Rede

Uma tela, cadastro único com hostname e IP/DNS, CSV e credenciais por sessão.

1. Adicione switches e, opcionalmente, o FortiGate da unidade.
2. Informe usuário e senha. Senhas diferentes e ajustes SSH ficam em Opções.
3. Clique em Mapear rede. Ao concluir, a aba Resultados abre com prévias de portas e dispositivos; use Abrir Excel para o relatório completo.

O modo completo não exige lista de MACs nem firewall. Sem FortiGate, descobre MACs nas portas de acesso; IPs e nomes dependem de informações disponíveis. O firewall acrescenta ARP/DHCP. As informações coletadas não garantem presença atual nem conexão física direta.

## Excel

- Portas: todas as interfaces coletadas, acesso/trunk, link, velocidade, VLANs, agregação, STP, PoE, mídia/transceptor, erros RX/TX, observações e LLDP consolidado.
- Dispositivos: IP, MAC, nome disponível, switch e porta de acesso, sem repetir uplinks.
- VLANs: redes criadas e seus dados disponíveis.
- Pendências: falhas de consulta e localizações que precisam de revisão.

Falhas na descoberta de dispositivos não descartam as portas coletadas. A aba de dispositivos não considera a falha em outro switch como motivo para invalidar uma localização observada. Dados técnicos ficam no JSON/log local, não como abas extensas.

## Localização rápida

Em MACs opcionais, informe os MACs e marque Somente localizar estes MACs. Nesse modo consulta apenas tabela MAC, configuração e LLDP dos switches, sem consultar o firewall ou coletar as demais informações de portas. O Excel contém Dispositivos e Pendências.

## Compatibilidade

As consultas comuns de configuração e LLDP são reutilizadas em memória. Cada switch usa uma sessão SSH na execução completa. A coleta é somente leitura; mantém verificação de chave SSH e validação dos destinos.

Cadastros antigos do localizador continuam disponíveis. Abrir cadastro também aceita o projeto antigo do mapeador de portas, preservando firewall e MACs atuais. CSVs de switches aceitam vírgula/ponto e vírgula e cabeçalhos nome/host/plataforma ou hostname/ip/tipo. Se a lista atual estiver vazia, inventario_portas.csv pode ser usado como cadastro inicial. Relatórios antigos ficam preservados localmente. Nenhum modelo Excel externo é necessário.

Mídia/transceptor mostra o valor coletado (por exemplo Copper ou Fiber), sem presumir o tipo quando o switch não o informa. LLDP consolida resumo, XML e detalhe quando identificam o mesmo vizinho/porta; portas distintas permanecem separadas.
