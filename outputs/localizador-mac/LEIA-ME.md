# Localizador de dispositivos por MAC

Integra FortiGate 7.4.9/7.4.12 (HA, sem VDOMs) com switches Cisco IOS/IOS-XE, NX-OS e Juniper EX/QFX por SSH. Descobre registros IPv4 por ARP e DHCP e cruza os MACs com as portas dos switches. Inclui também MACs aprendidos somente nos switches. Não suporta a tabela bridge dos Juniper MX nesta versão.

No FortiGate, executa apenas `get system status`, `get system ha status`, `get system arp` e `execute dhcp lease-list`. Trata paginação sem alterar a configuração do console e não provoca failover nem limpa tabelas. Não executa varredura/ping.

## Uso

1. Instale as dependências uma vez, pelo PowerShell na pasta da automação:

```powershell
python -m pip install -r .\requirements.txt
```

2. Abra **Iniciar.pyw** com dois cliques (se a associação Python estiver configurada), ou execute **localizar.py** no VS Code. Sem argumentos, ele abre a interface gráfica. Também pode abrir com:

```powershell
python .\localizar.py
```

3. Na aba **FortiGate**, preencha nome e IP/DNS do cluster e clique em **Adicionar**. Na aba **Switches**, cadastre nome, IP/DNS e plataforma de cada switch. Os CSVs existentes são carregados na primeira abertura; confira e substitua exemplos antes da coleta. Para editar uma linha, selecione-a, altere os campos e clique em **Atualizar selecionado**.
4. Na aba **Coleta**, informe o usuário SSH e as senhas. Marque **Usar a senha padrão dos switches também no FortiGate** se forem iguais. Contas diferentes podem ser preenchidas no campo Usuário específico de cada equipamento. Grupos de senha permitem credenciais distintas sem gravá-las em arquivo.
5. Clique em **Iniciar coleta**. A aba **Resultados** mostra progresso, erros e uma prévia dos primeiros 500 registros. Ao terminar, use **Abrir Excel** ou **Abrir pasta do resultado**. O Excel contém todos os registros, inclusive os marcados **A revisar**.

Use **Salvar projeto** para guardar os cadastros e opções sem senhas. O arquivo padrão `projeto_coleta.json`, salvo junto ao programa, é carregado automaticamente na próxima abertura. Outros projetos podem ser escolhidos com **Abrir projeto**. As senhas ficam somente na memória desta sessão; abrir outro projeto limpa os campos de senha. As abas de inventário também permitem importar/exportar CSV.

O modo **integrado** é o padrão. A aba **MACs opcionais** só participa desse modo quando a opção de acrescentar a lista estiver marcada. No modo **lista**, a lista de MACs é obrigatória e o FortiGate não é consultado.

A coleta roda em segundo plano, mantendo a janela responsiva. Aguarde a conclusão antes de fechar. Mudanças nos campos após iniciar valem para a próxima coleta. Os inventários devem representar a mesma unidade/domínio de rede; não misture unidades independentes com endereços reutilizados.

O modo de terminal continua disponível: `python localizar.py --modo integrado` ou `python localizar.py --modo lista`. Nesse modo, os inventários vêm dos CSVs e as credenciais são solicitadas no terminal; projetos da interface não são usados. Se `firewalls.csv` estiver vazio no modo integrado de terminal, o cadastro é solicitado e salvo sem senha.

Cada execução cria `resultados/DATA_HORA/localizacao_macs.xlsx`, `coleta.json`, `fortigate.json` (modo integrado) e uma pasta `logs` com as respostas das consultas operacionais. A configuração completa não é gravada. Os arquivos de resultados contêm dados internos da rede.

## Inventários e lista opcional

Mantenha o separador vírgula e salve os CSVs em UTF-8. O nome no inventário é o nome mostrado no Excel; use nomes únicos.

`firewalls.csv` (o arquivo entregue contém apenas o cabeçalho; substitua os valores do exemplo pelos reais):

```csv
nome,host,porta,usuario,password_env
FW-UNIDADE,192.0.2.1,22,,FG_PASSWORD
```

O usuário vazio reutiliza o informado para os switches. Preencha `usuario` se as contas forem diferentes. `FG_PASSWORD` e `SW_PASSWORD` solicitam senhas separadas; para reutilizar uma senha, use o mesmo nome de credencial nos dois inventários. Não coloque senhas nos CSVs.

`switches.csv`:

```csv
nome,host,plataforma,porta,usuario,password_env,secret_env
SW-ANDAR-01,192.0.2.10,cisco_ios,22,,SW_PASSWORD,
SW-ANDAR-02,192.0.2.20,juniper_junos,22,,SW_PASSWORD,
```

Usuário vazio: pergunta uma vez e reutiliza. `password_env` indica o nome de uma variável de ambiente ou de uma credencial a perguntar; não coloque a senha nesse campo. Use nomes diferentes se os switches tiverem senhas diferentes. `secret_env` fica vazio normalmente; para Cisco que exige enable, informe `SW_ENABLE` para solicitar essa senha separadamente.

`macs.csv`:

```csv
nome,mac
IMPRESSORA-RH,AA:BB:CC:DD:EE:FF
CAMERA-ENTRADA,0011.2233.4455
```

Para acrescentar essa lista à descoberta automática: `python localizar.py --macs macs.csv`. Para usar somente a lista e os switches, sem firewall: `python localizar.py --modo lista`. O modo integrado não lê `macs.csv` automaticamente, evitando incluir exemplos ou uma lista antiga por engano.

## Excel

O arquivo `localizacao_macs.xlsx` usa automaticamente o modelo incorporado `modelo_correspondencia.xlsx`, baseado em Correspondencia_Portas_MAC_v1.xlsx. Mantenha esse arquivo e `modelo_excel.py` junto de `localizar.py`.

- **Mapeamento de Portas**: uma linha por MAC, somente portas de acesso. Repetições do mesmo MAC/switch/porta são consolidadas e VLANs reunidas. Se houver mais de uma porta de acesso candidata, Switch e Porta ficam **A revisar**; consulte Ocorrências. IPs sem MAC ficam em linhas separadas para revisão. Altura das linhas de 45 pontos e observações curtas, com detalhes nas abas auxiliares.
- **Busca por MAC**: digite no campo amarelo; aceita dois-pontos, hífens, pontos ou somente os 12 dígitos. Mostra o resultado compacto da aba principal, incluindo A revisar em casos ambíguos. As fórmulas recalculam ao abrir no Excel.
- **Instruções**: orientações do modelo adaptadas à coleta automática.

IP e hostname vêm dos registros ARP/DHCP, quando disponíveis. A coluna opcional `ip` do `macs.csv` também é aceita. Nomes manuais têm prioridade; IPs diferentes são preservados. IP desconhecido fica vazio e nunca é substituído pelo IP do switch. VLAN da porta vem do switch; o nome da interface do firewall aparece nas observações e nos detalhes, sem presumir um VLAN ID a partir do nome.

As abas de diagnóstico continuam no mesmo arquivo:

- **Localização**: uma linha por MAC solicitado, resultado, portas candidatas e cobertura da consulta.
- **Ocorrências**: somente candidatas de acesso, uma linha por MAC/switch/porta, com VLANs consolidadas. Uplinks, trunks, agregações e portas sem modo access confirmado não entram no relatório de portas. As respostas completas permanecem nos logs e no coleta.json para diagnóstico.
- **Coleta**: switches consultados, quantidade de entradas, horário e erros. Falha de acesso ou formato não reconhecido não é tratada como ausência confirmada do dispositivo.
- **Descoberta FortiGate**: IP, MAC, hostname, interface e origem ARP/DHCP, preservando a resposta de cada fonte.
- **Coleta FortiGate**: versão, modo/estado HA, status de cada consulta e erros.
- **A revisar**: sem MAC, sem porta candidata, múltiplas candidatas, IP associado a MACs diferentes no mesmo escopo ou cobertura parcial. Quando um firewall falha, os dados disponíveis dos switches continuam no Excel, marcados para revisão.

ARP e leases podem estar antigos; um lease não comprova que o cliente esteja ligado. Um IP remoto alcançado por roteador não revela o MAC do host final. Hosts silenciosos, IPv6 e redes cujo gateway é outro equipamento podem ficar fora da descoberta. DHCP hospedado em servidor externo não aparece como concessão local no FortiGate. A coleta não promete inventário de todos os equipamentos ativos.

Inclua todos os switches no caminho, desde o core até os switches de acesso. O LLDP precisa estar habilitado e autorizado para consulta. Sem ele, o programa ainda pesquisa a tabela MAC, mas não consegue confirmar a relação entre switches. Não aplica mudanças para habilitar LLDP.

Uma porta candidata de acesso é aquela com modo access configurado, aprendizado dinâmico e sem vizinho LLDP identificado como outro switch cadastrado. Isso não prova ligação física direta: telefone, AP, hipervisor ou switch não gerenciado podem estar entre a porta e o dispositivo. Em agregações, a tabela pode informar apenas ae/Port-channel, sem determinar o cabo físico.

MACs descobertos somente em uplinks/trunks/agregações são omitidos da descoberta automática apresentada. Um MAC vindo do firewall ou da lista manual, mas sem acesso identificado, continua **A revisar**. Não se escolhe arbitrariamente entre duas portas de acesso. Entradas estáticas/especiais não comprovam presença. Ausência da tabela também não comprova dispositivo desligado: entradas expiram e equipamentos silenciosos podem não aparecer.

A janela adapta a altura à tela e reserva espaço para a barra de ações. Os botões quebram em mais de uma linha quando necessário, inclusive nas abas de cadastro.

## Primeiro SSH e erros

A identidade SSH dos switches e do FortiGate é verificada pelo arquivo conhecido do usuário (`~/.ssh/known_hosts`). Se o equipamento ainda não estiver registrado, conecte por `ssh usuario@IP` e valide a impressão digital com uma fonte confiável antes de aceitar. Não é necessário repetir esse processo a cada execução. Mudanças de chave devem ser investigadas.

Pode indicar outro arquivo com `--known-hosts CAMINHO`. Outros argumentos opcionais: `--switches CAMINHO`, `--firewalls CAMINHO`, `--macs CAMINHO`, `--modo integrado`, `--modo lista`, `--usuario NOME`, `--timeout 90`, `--workers 4`.

O usuário SSH precisa de permissão para tabela MAC, configuração e LLDP. Um Excel pode ser gerado mesmo com falhas; confira a aba Coleta. Código de saída 0 indica execução sem erros registrados, 2 indica erros/limitações de coleta, 1 indica erro de entrada ou dependência. Entradas CPU/remotas sem porta local reconhecida são reportadas como limitação; não se convertem em uma localização inventada.

Mantenha juntos `Iniciar.pyw`, `interface.py`, `localizar.py`, `fortigate.py`, `fortigate_ssh.py`, `modelo_excel.py`, `modelo_correspondencia.xlsx`, `requirements.txt` e os inventários. Na atualização, preserve seus CSVs e projetos já preenchidos. `interface.py` apresenta a janela; `fortigate.py` faz a descoberta/correlação; `fortigate_ssh.py` trata a sessão SSH do firewall.

Validação local usa amostras simuladas FortiGate/Cisco/Juniper, falhas SSH e geração/leitura do Excel. Não houve consulta a equipamento real nesta revisão. A compatibilidade com a saída e permissões de cada equipamento deve ser verificada na primeira coleta.

Referências dos comandos: [ARP na documentação Fortinet](https://docs2.fortinet.com/document/fortigate/7.4.0/administration-guide/473534/arp-table) e [listagem de leases DHCP](https://community.fortinet.com/fortigate-3/technical-tip-dhcp-address-leases-on-a-fortigate-97322).
