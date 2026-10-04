# Gerador FortiGate 60F e 40F — configuração completa para restauração

Base incorporada: **FGT60F / FortiOS 7.4.9 / build 2829**. O cabeçalho original e a configuração completa do arquivo `Script_base_60F.conf` são preservados. Com o modo automático desmarcado e sem outras alterações, a saída é literalmente igual ao arquivo-base de 18.447 linhas. O modo automático, habilitado inicialmente, pode ampliar faixas DHCP da base para seguir a regra solicitada.

## Abrir e usar

Extraia o ZIP inteiro e execute `gerar.py` pelo VS Code ou, na pasta extraída, pelo PowerShell:

```powershell
python .\gerar.py
```

Não precisa instalar pacotes via pip: usa Python padrão e Tkinter, normalmente incluído no Python Windows. Mantenha todos os arquivos e a pasta `bases` juntos.

Selecione **Tipo de script / firewall** no topo da janela. Disponíveis: **60F — FortiOS 7.4.9 / build 2829** e **40F — FortiOS 7.4.12 / build 2902**. A troca carrega interfaces e parâmetros da base selecionada. Projetos identificam sua própria base. A base 40F não possui RDI e mantém o bloco adicional append member do grupo GP_SV_PROXY. Credenciais e cabeçalho são preservados; restauração em hardware real ainda não validada.

1. **Unidade / HA:** hostname, localização SNMP, nome/ID do cluster e prioridade. Nome do cluster é separado do hostname.
2. **Interfaces:** IP/prefixo das 15 interfaces que já possuem IPv4 na base, incluindo LAN, voz, RDI, impressoras, TRUNK_SWAG, links e túneis. Exemplo: `10.50.20.254/24`. Os nomes, VLAN IDs e membros físicos não são renomeados.
3. **LINK1 / LINK2:** gateway, designação, alias e banda em Kbps. Escolha BASE, VIVO, EMBRATEL ou TERCEIRA e confira os peers preenchidos. IP local do túnel também está disponível aqui, sincronizado com a aba Interfaces.
4. **DHCP existente:** no modo automático, faixas das redes principais são calculadas do primeiro host até gateway menos dois. Desative o modo automático na aba Interfaces para informar faixas manualmente. Não são criados novos servidores.
5. **Validar / revisar alterações:** veja onde cada parâmetro foi alterado, com antes/depois. Senhas não aparecem no relatório.
6. **Salvar configuração completa:** exporta o `.conf` completo para o fluxo de restauração, e não uma sequência curta de comandos CLI. O relatório pode ser salvo separadamente.

Use **Salvar projeto** para reutilizar os campos nas próximas unidades. O projeto JSON não contém as credenciais da base. Carregar projeto valida os dados antes de preencher a janela.

### Aba BGP e prévia visual

A aba **BGP** reúne os quatro neighbors e seus AS remotos. Os campos são compartilhados com as abas LINK1/LINK2: alterar um neighbor atualiza o IP remoto da VPN, e vice-versa, inclusive ao selecionar uma operadora.

Os cinco **networks** existentes mostram a rede automática e o prefixo que será anunciado. Com a opção Automático marcada na aba Interfaces, acompanham as redes das interfaces e os campos manuais ficam desabilitados. Desmarcando, um campo manual vazio continua acompanhando a interface; preenchê-lo substitui somente o anúncio BGP. Prefixos inválidos ou duplicados são bloqueados. Projetos antigos sem a nova opção abrem com ela desmarcada, preservando o comportamento anterior.

Na aba **Revisão**, a opção **Destacar alterações** mostra o valor anterior em vermelho e o novo em verde, com rótulos Antes/Depois. Pode desmarcar para visualizar sem cores. A prévia é somente leitura e é invalidada ao editar os campos, para não mostrar uma revisão desatualizada. O relatório continua sem credenciais.

## Senhas: preservação obrigatória

Como solicitado, **nenhuma senha é removida, substituída, decodificada ou recriptografada**. Isso inclui admin local, usuários, TACACS principal/secundário, HA, VPN PSKs e demais valores ENC. Certificados também são preservados.

O motor compara literalmente todos os 82 comandos de credenciais/certificados identificados na base antes de permitir a saída. Uma alteração bloqueia a geração. As chaves da planilha MOP não são importadas nem usadas para substituir chaves da base.

Consequentemente, tanto o arquivo na pasta `bases` quanto o `.conf` exportado contêm as credenciais originais, como você pediu. Proteja o pacote e os resultados. Preservação literal não comprova que uma chave será aceita pelo destino/peer: ao mudar a operadora, a PSK continua a do túnel da base e precisa corresponder à configuração do HUB/EQX.

## Dependências que são atualizadas

| Entrada | Configurações relacionadas |
|---|---|
| Hostname | `system global`, descrição SNMP do FortiGate e descrição SNMP em `switch-controller`; todas as três referências literais identificadas |
| IP da LAN | Router-id BGP; origem de DNS, NetFlow, FortiManager, syslog, FortiAnalyzer, NTP e TACACS |
| Sub-redes | Objetos de `firewall address` com subnet original correspondente; prefixos anunciados em `router bgp network` |
| LAN | Inclui `n_REDE_LAN`, `n_LAN_VL_200`, `n_LAN_Localidade` e `LAN_VLAN_200 address` |
| Voz, impressoras, RDI | Objetos de endereço correspondentes, BGP e DHCP existente quando houver |
| TRUNK_SWAG | Endereço `LAN_VLAN_1171`, anúncio BGP, DHCP e registro DNS local do FortiSwitch |
| Interface com DHCP | Gateway, máscara, faixas e reservas existentes; preserva MAC, lease, opções e servidores corporativos |
| Gateway LINK1/LINK2 | Membro SD-WAN correspondente ao link |
| Descrição, alias e banda do link | Interfaces do link e seus túneis; banda dos respectivos membros SD-WAN |
| Peer público / IDs | `remote-gw`, `localid` e `peerid` da phase1 correspondente |
| IP remoto do túnel | Interface do túnel, chave do neighbor BGP e chave do neighbor SD-WAN |
| AS remoto | Neighbor BGP do túnel correspondente |
| Alteração de peer/IP do túnel | Associa o neighbor SD-WAN ao ID do membro de túnel já existente, sem copiar IDs fixos do MOP |

São atualizados valores em campos específicos; não há substituição cega de todos os IPs do texto. Redes de serviços corporativos não são tratadas como redes locais. Objetos e políticas que referenciam nomes continuam com os mesmos nomes.

## DHCP e mudança de máscara

Há servidores na base para quarantine, rspan, nac_segment, voz, impressoras, TRUNK_SWAG e LAN. **Não existe servidor RDI na base e nenhum será criado.**

Na aba Interfaces, a opção **Automático: redes das interfaces → DHCP, BGP e firewall address** fica marcada inicialmente. Para LAN, impressoras, voz e TRUNK_SWAG, a faixa DHCP começa no primeiro IP utilizável e termina no IP da interface (gateway) menos dois. Exemplo: `10.50.20.254/24` gera DHCP `10.50.20.1` até `10.50.20.252`, anúncio BGP `10.50.20.0/24` e os objetos firewall address nessa mesma rede. Para `10.50.20.6/29`, a faixa será `.1` até `.4`. A interface deve ser informada com um IP de host e máscara, não somente o endereço de rede.

RDI atualiza BGP e firewall address, mas não ganha servidor DHCP porque não há um configurado na base. Os servidores auxiliares quarantine/rspan/nac_segment mantêm a regra anterior. Campos DHCP/BGP manuais ficam desabilitados e são ignorados enquanto a opção automática estiver ativa; os valores são conservados no projeto para quando ela for desmarcada.

As reservas DHCP continuam mantendo o deslocamento a partir da rede original e o mesmo MAC. Ao desmarcar Automático, campos DHCP vazios também voltam a manter o deslocamento das faixas originais; podem ser preenchidos manualmente. A base original LAN usa `.193` até `.238` na rede `192.0.2.192/26`; esse modo anterior resultaria em `.1` até `.46` numa nova rede /24, enquanto o novo automático usa gateway menos dois.

Reduzir a rede pode tornar uma faixa ou reserva inválida: a geração é bloqueada para evitar truncamento silencioso. Reservas não são recriadas com outros MACs nesta revisão. DNS/NTP corporativos e opções DHCP, inclusive os valores hexadecimais existentes, permanecem como na base.

## Operadoras e VPNs

TERCEIRA é uma opção para LINK1 ou LINK2; não cria um LINK3. Existem quatro túneis, HUB e EQX de cada link. Os campos vêm das abas de VPN do arquivo `MOP - VPNs.xlsx`:

| Perfil | HUB público | HUB remoto/BGP | EQX público | EQX remoto/BGP |
|---|---|---|---|---|
| VIVO | Definido na base local | Definido na base local | Definido na base local | Definido na base local |
| EMBRATEL | Definido na base local | Definido na base local | Definido na base local | Definido na base local |
| TERCEIRA | Definido na base local | Definido na base local | Definido na base local | Definido na base local |

AS HUB 65001 e AS EQX 64543, editáveis nos respectivos campos. Os IDs são os literais de cada aba do MOP, inclusive EMBRATEL EQX usando `BGP-ISP-L3`. O programa não troca esse valor por inferência.

Os IPs locais de túnel devem ser preenchidos para a unidade. O perfil não inventa nem deriva novos IPs locais dos exemplos da planilha. Se escolher a mesma operadora para os dois links, os peers predefinidos se repetirão: o gerador bloqueia e você deverá fornecer conjuntos de peers realmente distintos.

O MOP é referência de parâmetros, não executado literalmente. Foram evitadas as inconsistências `edit interface` em VPN_L3_HUB!A68 e o membro SD-WAN apontando para LINK físico em VPN_L3_HUB!A49. A numeração SD-WAN e as referências existentes são as da base do 60F. As propostas, phase2, DH, DPD, NAT traversal, offload e PSKs da base são preservados; selecionar operadora não reaplica todos os comandos do MOP.

## Itens herdados que precisam de revisão operacional

- A base contém FortiSwitches gerenciados, números de série, nomes de unidade, certificados e políticas da origem. Nesta etapa só as referências literais ao hostname completo do FortiGate são atualizadas. Não há renomeação geral de DA68, migração de switches ou substituição de seriais/MACs.
- Algumas regras SD-WAN EQX têm `priority-members 67 57`, enquanto o membro 57 é HUB. Isso já está na base; as regras são preservadas, sem correção automática.
- Alguns neighbors SD-WAN não possuem `member` explícito na base. Se o peer/IP do túnel for editado, o gerador inclui o membro correto do túnel. Sem alterações, permanece a base literal.
- Certificados podem estar ligados à identidade do equipamento de origem. O gerador não emite certificados novos.
- Modo HA, senha HA, heartbeat, criptografia, políticas, AS local e demais configurações não expostas no formulário permanecem iguais.
- Não adiciona interfaces, VLANs, servidores DHCP, túneis, links ou modelos novos nesta revisão.

## Arquivos e futuras bases

- `gerar.py`: interface gráfica.
- `motor.py`: relações e validações específicas desta base.
- `config_tree.py`: leitor/editor que preserva os comandos originais e conteúdos multilinha.
- `bases/60F_7.4.9.conf`: cópia integral do arquivo fornecido, com credenciais originais.
- `bases/catalogo.json`: modelo, versão, build e SHA-256 da base.
- `bases/operadoras.json`: endpoints/IDs/AS não secretos extraídos do MOP.
- `LEIA-ME.md`: instruções.

Não altere o arquivo-base diretamente: o hash é verificado. Cada novo modelo/firmware precisará de cadastro próprio e revisão das dependências. Não são fabricados cabeçalhos para outras versões.

## Validação e restauração

25 testes locais cobrem saída idêntica sem alterações, conteúdo multilinha, hostname, dependências da LAN, todas as redes principais, DHCP/reservas, máscara menor, gateway /31, troca de operadoras, terceira operadora, túneis/BGP/SD-WAN, HA, credenciais, blocos não relacionados, entradas inválidas e abertura/revisão da janela.

Os testes locais não equivalem a restaurar no equipamento. Não houve acesso nem teste em FortiGate real. Use o fluxo de restauração somente no 60F com firmware compatível, mantendo backup do destino e console disponível. Revise o relatório e os itens herdados. Após restaurar, confira erros de configuração, gerenciamento, HA, DHCP, VPNs, BGP, SD-WAN e autenticação.

Referência de BGP consultada: https://docs.fortinet.com/document/fortigate/7.4.9/cli-reference/225427711/config-router-bgp


A aba Firewall address exibe todos os objetos correspondentes a LAN, voz, RDI, impressoras e TRUNK_SWAG, com rede original e prevista em CIDR. Atualiza ao editar interfaces e destaca mudanças em verde.
