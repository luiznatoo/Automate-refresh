# Mapeamento de portas — tela simplificada

1. Clique em Adicionar switch: hostname, IP/DNS e tipo (Juniper, Cisco IOS ou Cisco Nexus).
2. Para vários switches, use Importar CSV. A importação acrescenta os novos equipamentos e ignora registros idênticos; conflitos são informados sem alterar a lista.
3. Informe usuário e senha abaixo da lista. Clique em Mapear portas e depois Abrir Excel.

Use Editar ou Remover para os equipamentos selecionados. Hostname vazio usa o IP. A senha fica somente na sessão e não é salva com o cadastro.

CSV aceita vírgula ou ponto e vírgula. Cabeçalhos: `hostname,ip,tipo` ou `nome,host,plataforma`. Tipos: `juniper_junos`, `cisco_ios`, `cisco_nxos` (também aceita Juniper, Cisco IOS e Cisco Nexus).

Em Opções ficam timeout, paralelismo, known_hosts, diagnóstico, grupos de senha adicionais, abrir/salvar cadastro e detalhes da coleta. No cadastro, Acesso específico permite alterar porta, usuário, grupo de senha, enable ou chave SSH quando necessário.

A coleta e o modelo Excel permanecem completos: portas de acesso e trunk, VLANs, agregações e LLDP. Nenhuma configuração é aplicada nos switches.

---

## Referência técnica anterior

# Mapeamento de switches por SSH → Excel

## Interface gráfica

Abra `Iniciar.pyw` ou execute `mapear.py` sem argumentos. A janela possui abas Coleta, Switches e Resultados, com botões adaptados a telas menores.

1. Confira os switches carregados de `inventario.csv`. Adicione ou edite equipamentos pela aba Switches; clique em Atualizar selecionado para aplicar a edição de uma linha.
2. Informe usuário e senhas na aba Coleta. Grupos diferentes permitem senhas por equipamento; enable e chave SSH são opcionais.
3. Clique em Iniciar mapeamento. A coleta roda em segundo plano e mostra o status de cada switch.
4. Use Abrir Excel ou Abrir pasta do resultado ao terminar. O modelo fixo, VLANs, LLDP, LACP, portas access e trunk continuam incluídos.

Salvar projeto guarda cadastros e opções, sem senhas. O arquivo `projeto_mapeamento.json` salvo junto ao programa é carregado na próxima abertura. Abrir projeto permite alternar entre unidades e limpa as senhas da sessão. A opção de diagnóstico gera o JSON adicional.

O terminal continua disponível quando há argumentos, por exemplo `python mapear.py --inventario inventario.csv`. A interface usa os mesmos coletores e exportador do terminal. Ao atualizar, preserve inventários, projetos e relatórios existentes.

## LLDP por porta e VLANs

Compatibilidade Junos antigo: usa `show lldp neighbors`, XML da listagem básica e `show lldp neighbors interface PORTA` apenas nas portas descobertas com vizinhos. Não usa o modificador global `detail`, introduzido no Junos 19.1R2. O identificador SNMP local numérico não é tratado como nome de porta. Se a coleta falhar, execute com `--diagnostico` para preservar as saídas necessárias à análise.

A aba Portas inclui a coluna U, `LLDP — Vizinho | Porta | Descrição | Chassis`. Cada linha mostra os vizinhos anunciados naquela porta; múltiplos vizinhos aparecem em linhas separadas na mesma célula. Junos usa consulta textual e XML complementar, e Cisco usa consulta textual/NTC. Ausência de informação não prova ausência de conexão: consulte Coleta para falhas ou LLDP desabilitado.

A aba VLANs lista Switch, VLAN ID, Nome, Instância, Descrição, Estado, Interfaces, Interface L3, Fonte e Coleta UTC. Combina VLANs da configuração e da tabela operacional, sem transformar toda VLAN permitida em um trunk em VLAN criada. Campos não fornecidos ficam vazios. O inventário e o comando de execução continuam iguais.

## Atualização: modelo fixo e coleta operacional

Execute `python mapear.py` na pasta do programa. O arquivo `modelo_fixo.xlsx` incluído é usado automaticamente; não é mais necessário passar `--modelo`. A execução gera **um único Excel**, com Portas, LACP, Legenda e Coleta. A aba Coleta registra horário, status e falhas. Não é mais produzido o Excel `_detalhado` mencionado nas instruções da versão anterior abaixo.

Para diagnóstico opcional, execute `python mapear.py --diagnostico`. Isso salva também um JSON com saídas operacionais (sem a configuração completa e sem credenciais). Esse JSON pode conter endereços e nomes internos. Os arquivos anteriores não são apagados.

Junos: há parsers próprios para interfaces terse/extensive, XML com namespaces, STP por VLAN, LACP e tabela PoE. O estado LACP é preenchido na aba Portas e na aba LACP. Uma consulta LACP extensive busca também prioridade e System ID quando retornados. Cisco: parsers adicionais para interfaces, STP e resumo EtherChannel, complementados por NTC Templates. As saídas são preservadas em memória antes do parsing, inclusive quando o parser falha, e podem ser exportadas com --diagnostico.

Velocidade/duplex refletem o valor operacional reportado pelo equipamento. Portas down podem não ter negociação atual; interfaces lógicas não possuem mídia/PoE próprios. Comandos indisponíveis, falta de privilégios e diferenças de versão ainda podem deixar campos não coletados. Não são inventados valores para preencher lacunas. Para Junos STP, unidades .0 são relacionadas à porta física; VLAN/instância é mantida. As portas usam ordenação natural (1, 2, 10).

Os testes locais incluem saídas sintéticas de interfaces/XML e reprodução de STP/LACP do relatório anterior. É necessária nova execução SSH para validar status, velocidade e contadores reais, pois a versão anterior descartou essas saídas ao ocorrer erro TextFSM.

Coletor para Python 3.10+ em Windows/Linux. Acesso CLI via SSH (porta 22 por padrão), sem necessidade de NETCONF. Executa consultas `show`, preparação de terminal pelo Netmiko e, se informado, `enable`. Não envia configuração aos equipamentos.

## Início no Windows

Instale Python 3.10 ou superior. Abra PowerShell na pasta extraída:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe mapear.py --inventario inventario.csv --usuario seu_usuario
```

Edite **inventario.csv antes de executar**: os endereços 192.0.2.x são exemplos fictícios. A senha é solicitada sem aparecer no terminal. O Excel será criado em `relatorios/` com data/hora no nome. Nenhum switch real foi acessado na preparação deste pacote.

## Plataformas

## Usar seu modelo Verificacao_Portas_C001

O coletor aceita o modelo com abas `🔌 Portas`, `⚡ LACP` e `📖 Legenda`:

```powershell
python mapear.py --inventario inventario.csv --modelo ".\modelo_fixo.xlsx"
```

Use o mesmo executável Python em que instalou as dependências. O arquivo original é preservado. A execução gera uma cópia no layout do modelo e um segundo Excel `_detalhado.xlsx` com evidências, horários e falhas. Os dados antigos de Portas e LACP são removidos da cópia antes do preenchimento, inclusive se a coleta falhar. A Legenda, larguras e cabeçalhos são preservados. Switch corresponde ao campo `nome` do inventário, não necessariamente ao hostname descoberto. Interfaces Junos com unidade `.0` são combinadas com a porta física para este layout.

São consultados STP, PoE e detalhes de interfaces. O preenchimento depende de suporte a comandos e templates na versão do equipamento. `Não coletado` ou `?` significa indisponível; não significa down, ausência de PoE ou contador zero. Velocidade configurada não substitui velocidade negociada. STP mantém o identificador de VLAN/instância quando fornecido pelo parser. Estado LACP, prioridade e System ID ainda devem ser consultados em LAG_operacional/Evidencias do relatório detalhado; a aba LACP do modelo apresenta membros e modo configurados, sem presumir estado de negociação.

O modelo recebido já menciona Resumo e Problemas na Legenda, mas não contém essas abas. A automação preserva essa legenda sem criar abas adicionais no modelo. O resumo da coleta fica no relatório detalhado.

## Plataformas suportadas

| Valor no CSV | Família |
|---|---|
| cisco_ios | Cisco IOS / IOS-XE |
| cisco_nxos | Cisco Nexus NX-OS |
| juniper_junos | Juniper Junos EX/QFX e equipamentos com CLI compatível |

Cisco Small Business, IOS-XR e sistemas diferentes dessas famílias não estão cobertos. Modelos e versões específicos precisam de uma primeira coleta de validação.

## Inventário e autenticação

Colunas obrigatórias: `nome`, `host`, `plataforma`. O host pode ser IP ou nome DNS. Campos opcionais:

- `porta`: porta SSH, padrão 22.
- `usuario`: sobrescreve `--usuario` para aquele equipamento.
- `password_env`: nome da variável de ambiente que contém a senha; padrão SW_PASSWORD se a coluna estiver ausente. Não coloque a própria senha no CSV.
- `secret_env`: nome da variável contendo a senha enable Cisco; deixe vazio se não precisa. O exemplo usa SW_ENABLE no primeiro Cisco; remova se a conta já tem privilégio suficiente.
- `key_file`: caminho para chave privada SSH, substituindo autenticação por senha. Esta versão não solicita passphrase de chave criptografada.

As chaves de host SSH são verificadas. Cadastre previamente a chave no arquivo `~/.ssh/known_hosts` usando o cliente OpenSSH e conferindo a impressão digital com o administrador. Exemplo: `ssh seu_usuario@IP_DO_SWITCH`. Também pode fornecer `--known-hosts C:\caminho\known_hosts`. Chaves desconhecidas ou alteradas causam falha, registrada no relatório.

## Conteúdo do Excel

- **Resumo:** resultado por switch (OK, PARCIAL, FALHA), data UTC e contagens.
- **Interfaces_config:** interfaces físicas e lógicas, descrição, modo explícito, VLAN access/voz/nativa, VLANs trunk/membros, IP, MTU, shutdown e associação a agregação quando configurados.
- **VLANs_config:** VLANs presentes na configuração; **VLANs_operacionais** complementa VLANs aprendidas ou padrões retornados pelo equipamento.
- **Agregacoes_config / LAG_operacional:** associação configurada dos membros e estado retornado pelo equipamento.
- **Estado_portas / Switchport / Detalhes_portas:** informações operacionais estruturadas conforme suporte dos templates.
- **Equipamento / Hardware / Enderecos_IP:** versão, modelo, serial e endereços quando disponíveis.
- **Vizinhos_LLDP / Vizinhos_CDP:** conexões anunciadas pelos equipamentos; CDP apenas Cisco. A descoberta depende dos protocolos habilitados e de vizinhos ativos.
- **Ocorrencias:** falhas de SSH, permissões, comandos ou interpretação.
- **Evidencias:** saídas operacionais para conferência quando não há template compatível. A configuração completa não é gravada, pois pode conter segredos.

Cada linha identifica equipamento, endereço de gerenciamento, horário UTC e comando de origem. As abas têm filtros e cabeçalho fixo. Dados recebidos dos switches são gravados como texto, sem executar fórmulas Excel.

## Como interpretar

Campo vazio significa **não explícito/não extraído**, nunca confirmação de valor padrão. A configuração e o estado operacional ficam separados: uma porta configurada trunk pode estar down ou negociando outro estado. No Junos, `ge-0/0/0` e `ge-0/0/0.0` são registros distintos; consulte ambos. VLAN nativa e descrição podem estar na interface física, enquanto o modo e os membros ficam na unidade lógica. Configuração do agregado não é copiada artificialmente para cada porta participante.

O Junos é consultado com `display inheritance | display set` para expandir grupos e interface ranges. Entradas explicitamente desativadas são excluídas. Se o comando não for suportado ou houver ranges residuais, revise Ocorrencias. Configurações Junos avançadas (routing-instances, bridge-domains, flexible-vlan-tagging, VLAN rewrite, EVPN/VXLAN e hierarquias especiais de voice VLAN) não têm interpretação completa nesta versão. VLAN voz Cisco é extraída; Junos voice VLAN não é normalizada.

Campos operacionais dependem de Netmiko/NTC Templates e da versão/idioma do sistema. Se não houver parser, o comando fica disponível em Evidencias e a coleta é PARCIAL. Uma saída vazia de LLDP também é registrada para revisão; isso pode significar simplesmente ausência de vizinhos. Não há descoberta recursiva de IPs: são coletados somente os hosts do CSV. A planilha fornece relações LLDP/CDP, não um desenho de topologia.

## Execução recorrente

Para Agendador de Tarefas do Windows ou cron, use caminhos absolutos e forneça credenciais por variáveis de ambiente do processo/conta de execução:

```powershell
.\.venv\Scripts\python.exe mapear.py --inventario C:\Redes\inventario.csv --usuario coletor --nao-interativo --workers 4 --timeout 90
```

Nenhum agendamento foi criado. O modo não interativo falha antes da coleta se faltar uma credencial necessária. Não grave senhas em argumentos nem em arquivos versionados; use uma conta de consulta com permissões para os comandos necessários. O Excel inclui inventário e endereços internos; armazene conforme as regras da sua rede.

O nome padrão evita sobrescrever relatórios anteriores. `--saida caminho.xlsx` escolhe um destino fixo e substitui o arquivo existente. Código de saída 0: coleta sem ocorrências; 2: relatório com ocorrências ou argumentos inválidos; outras falhas de execução retornam erro. Feche a planilha no Excel antes de substituir um destino fixo.

## Testes e referências

```powershell
.\.venv\Scripts\python.exe -m unittest -v
```

Testes sintéticos cobrem VLANs/ranges/add/remove/except, access/voz, agregações, Junos físico/lógico, nomes de VLAN e exclusão de configuração desativada. Não substituem validação com seus modelos e versões. Não foi feita validação SSH em equipamento real nem geração de inventário real.

- Netmiko: https://ktbyers.github.io/netmiko/docs/netmiko/
- NTC Templates: https://github.com/networktocode/ntc-templates
- Juniper display inheritance: https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-pipe-display-inheritance.html
