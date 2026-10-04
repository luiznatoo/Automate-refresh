# FortiSwitch 148E — restauração completa

Esta revisão substitui a geração anterior de comandos CLI. A base completa já vem no pacote: não precisa selecionar um backup a cada execução.

## Uso

Extraia o ZIP inteiro e execute gerar.py pelo VS Code ou Python. Não precisa de pip; usa Tkinter incluído normalmente no Python Windows.

1. Preencha hostname, IP/prefixo, gateway, VLAN de gerenciamento e localização.
2. Preencha VLANs e grupos de portas.
3. Informe as duas chaves TACACS/ISE, comunidade SNMP e nova senha do admin local.
4. Use Validar / prévia e Salvar restauração .conf.
5. Salve projetos sem senhas para reutilizar nas próximas unidades.

## Base disponível

148E não PoE, 52 portas, 1.346 linhas no arquivo-base fornecido pelo usuário.
Cabeçalho preservado: S148EN-7.04-FW-build929-250909.
Rótulo: Base 7.04 / build 0929. Não deduzimos uma versão de patch apenas desse identificador.

NÃO é uma base 7.6.6. Não há conversão de firmware nem alteração artificial de cabeçalho. Confirme modelo e firmware/build compatíveis no destino. 148E PoE e outros modelos/builds ainda não estão disponíveis para restauração. Se o destino estiver em 7.6.6, esta base não atende a essa versão.

## Preservação

A edição é estrutural sobre o backup completo. Cabeçalho e blocos não envolvidos ficam preservados: ACLs, certificados, perfis LLDP, QoS, velocidades físicas, índices SNMP, instâncias STP e parâmetros gerais.

Na restauração, os valores herdados são os DA BASE, não os existentes no switch de destino. Portas e VLANs omitidas permanecem como na base. DNS/NTP/syslog deixados vazios também são herdados, não desabilitados. VLANs antigas não são removidas automaticamente.

O acesso internal original (DHCP e secundário 192.168.1.99), suas permissões, VLAN interna 900 e descoberta FortiLink/auto-ISL são preservados nesta revisão. Não foi aplicado saneamento automático desses parâmetros. A base é seu modelo fornecido, não um padrão universal de fábrica.

## Alterações do formulário

- Hostname e interface LAN_VLAN_200: IP/máscara, VLAN, alias, ping/HTTPS/SSH/SNMP. Nome da interface fixo nesta base, mesmo quando o ID da VLAN muda.
- VLAN de gerenciamento na lista allowed-vlans de internal, mantendo a outra VLAN original; gateway/interface da rota padrão 1.
- VLANs informadas: criação/descrição. Portas informadas: descrição, nativa, tagged e limpeza de untagged adicionais.
- Portas editadas: STP habilitado; acesso com edge/BPDU guard/loop guard e descarte de quadros tagged; trunk sem essas proteções de borda. Isso altera os trunks originalmente com STP desabilitado.
- TACACS/ISE: servidores, chaves, origem no IP de gerenciamento, ASCII, grupos e administrador remoto ISE. Ambos os servidores devem ser preenchidos nesta base. O grupo escolhido atende o login; o segundo não vira failover automático.
- Perfil local prof_admin de leitura/escrita. Com perfil retornado, autorização/override e fallback noaccess: o servidor precisa devolver o perfil correto.
- Nova senha obrigatória para admin local; senha original removida do pacote.
- SNMP: contato/local/descrição/comunidade e substituição integral dos hosts da comunidade 1, retirando entradas vazias. Consultas v2c; v1 e traps desabilitados. Sem SNMPv3 nesta revisão.
- DNS/NTP/syslog preenchidos: parâmetros correspondentes atualizados; demais opções dos blocos preservadas.

## Formatos

VLANs, uma por linha: ID;descrição
Exemplo: 200;GERENCIA_LAN

Acessos: portas;VLAN;descrição
Exemplo: 1-46;200;USUARIOS

Trunks: portas;VLAN nativa;VLANs tagged;descrição
Exemplo: 47-52;1;104,105,200;UPLINK

Todas as VLANs usadas precisam estar cadastradas. Não repita portas nem a nativa entre as tagged. Acesso é sem tag, sem voice VLAN. Trunk de VLANs não é LACP. São validados intervalos, conflitos, IP/gateway e transporte da VLAN de gerenciamento.

## Arquivos

- gerar.py: janela e validações.
- restauracao.py: leitura estrutural e edição da base.
- bases/catalogo.json: identidade, origem, hash e estado da base.
- bases/148E_build0929.conf: configuração sanitizada com marcadores de credenciais. NÃO RESTAURE DIRETAMENTE; gere o arquivo final pelo programa.
- LEIA-ME.md: instruções.

Não altere a base manualmente: o hash é verificado. Novos modelos/builds serão incorporados como revisões próprias, com revisão de referências e testes. Adicionar um item no catálogo sozinho não habilita um modelo sem revisar o gerador.

## Credenciais e restauração

As senhas/chaves ENC e a comunidade do equipamento de origem foram removidas. A exportação bloqueia marcadores não substituídos. O .conf final contém as novas credenciais em texto claro: proteja o arquivo. Projetos JSON e prévia ocultam esses segredos.

Faça backup do destino e mantenha console disponível. Restaurar substitui a configuração e pode reiniciar o equipamento. Confira erros, IP/gateway, VLANs/portas, login local, login remoto em outra sessão e consulta SNMP. O programa não restaura remotamente.

30 testes locais verificam validações, preservação literal, credenciais, gerenciamento, SNMP, restrição modelo/build e inicialização/prévia da janela. A restauração em hardware NÃO foi testada; estrutura validada não garante aceitação pelo firmware.
