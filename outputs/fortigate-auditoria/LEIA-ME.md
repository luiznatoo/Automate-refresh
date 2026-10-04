# Auditoria de Firewall — somente leitura

Abra Auditoria de Firewall na Central. Cadastre os equipamentos manualmente ou importe CSV. Este módulo não aplica configurações. O Hardening está separado na Central, com cadastro e resultados próprios.

## Como usar

Abra pela Central de Refresh ou execute interface.py (Python com requirements.txt instalado).
1. Cadastre os firewalls manualmente ou importe o inventario.csv preenchido. Não há limite de 100 linhas.
2. Informe usuário e senha na aba Acesso SSH. Use Exportar CSV/Importar CSV para reutilizar a mesma lista no Hardening.
3. Ajuste as regras na segunda aba e inicie a auditoria. O Excel fica em resultados, junto das regras utilizadas.

Campos obrigatórios: nome e host. Porta padrão 22. Usuário por equipamento é opcional e prevalece sobre o usuário da tela. A senha da tela é compartilhada nesta versão, mantida somente em memória. Não coloque senhas no CSV.
Modelo esperado deve usar a identificação do get system status, por exemplo FortiGate-60F. Versão usa 7.4.9, sem build. HA: a-p, a-a ou standalone. Expectativas em branco não validam o padrão corporativo daquele campo. BGP e VPN aceitam listas separadas por | (IP do vizinho e nome exato da VPN).

Regras iniciais: hostname/modelo/versão esperados; modo e sincronismo HA; BGP estabelecido; seletores VPN ativos; ausência de HTTP/Telnet administrativo nas interfaces; timeout administrativo até 10 minutos. Os limites são configuráveis. VPN sob demanda pode aparecer inativa: ajuste a política conforme o uso. Listas esperadas detectam sessões ausentes; sem elas, a auditoria considera somente sessões observadas.

Resultados: Conforme, Não conforme, Não aplicável e Não foi possível verificar. Falha de autenticação, comando recusado e formato desconhecido não significam conformidade. Este módulo verifica o estado atual esperado para refresh; a comparação pré/pós continua na ferramenta RDM. Não é uma certificação CIS nem uma auditoria completa de vulnerabilidades. Escopo: sem VDOM; nenhuma configuração é alterada.

Conexões simultâneas: padrão 4, máximo 16. Timeout vale por comando. A interface permanece disponível durante o processamento. A chave SSH precisa estar no known_hosts do usuário ou no arquivo selecionado; a ferramenta não aceita automaticamente chaves desconhecidas. Cadastre/verifique a chave do equipamento previamente pelo processo SSH da empresa.

O Excel contém Resumo e Resultados com evidências selecionadas. Não são gravadas configurações brutas nem senhas. Falhas de coleta podem exigir revisão manual das permissões/comandos no equipamento. Valide primeiro em algumas unidades antes de ampliar o lote.

Referências técnicas:
- https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/215451/setting-the-idle-timeout-time
- https://docs.fortinet.com/document/fortigate/7.4.0/best-practices/103945/administrative-settings
