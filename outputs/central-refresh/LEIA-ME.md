# Central de Refresh — interface simplificada

Escolha a ferramenta e clique em **Abrir**. A tela inicial está organizada em Verificar a rede e Gerar configurações.

- **Opções → Equipamentos e acesso:** cadastro central e senhas da sessão, opcionais. Continue usando o cadastro dentro de cada ferramenta se preferir. A unidade/grupo escolhidos aparecem no rodapé da Central.
- **Histórico:** botão no rodapé; clique duas vezes em um registro para abrir seu arquivo.
- **Opções → Atualização:** instalar pacote ZIP ou trazer dados da versão anterior.
- **Opções → Arquivos e ajuda:** escolha a ferramenta para consultar versão, instruções e pasta de resultados.

As ferramentas, coletas, aprovações e dados mantêm o funcionamento existente. Fechar a Central não fecha ferramentas já abertas. Senhas permanecem somente durante a sessão.

---

# Central de Refresh 2.0.0

Abra CentralRefresh.exe no pacote Windows mantendo todas as pastas ao lado. Para executar o código-fonte, abra central.py com as dependências instaladas e refresh_core na mesma raiz ou na pasta pai.

## Cadastro central

Cadastre primeiro as unidades e os grupos de credenciais, depois os equipamentos. O grupo guarda usuário, nome da variável de senha, variável enable opcional e caminho absoluto de chave SSH opcional. Não digite senhas nesses campos. O CSV de equipamentos usa unidade;nome;host;porta;plataforma;grupo. Plataformas: fortinet, juniper_junos, cisco_ios e cisco_nxos. Uma importação inválida não substitui o cadastro anterior.

Selecione a unidade e opcionalmente um grupo na tela principal. Cadastro local mantém os cadastros próprios dos módulos. Ao abrir um coletor, o inventário selecionado é preenchido sem iniciar conexões. Hardening recebe FortiGates, mapeamento recebe switches e localizador recebe ambos. Geradores continuam utilizando seus projetos específicos.

Senhas da sessão permite informar senha SSH e enable por grupo. Nada é salvo no cadastro ou despachos; senhas são repassadas por variáveis de ambiente aos processos filhos. Fechar a Central limpa sua cópia; ferramentas já abertas mantêm sua própria sessão. Se não fornecer na Central, preencha no módulo. Enable exige uma referência de variável definida no grupo.

Hardening utiliza uma senha por lote na interface: selecione um grupo quando houver senhas diferentes na unidade. A interface desse módulo não recebe chave SSH. Switch mapper e localizador aceitam grupos distintos por equipamento. As chaves conhecidas SSH continuam obrigatórias; nenhuma chave de host desconhecida é aceita automaticamente.

## Transporte e histórico

refresh_core/ssh.py é o transporte FortiGate compartilhado: chave conhecida, paginação, timeout, limite de saída e aceite de banner pós-login. Cada módulo mantém sua lista própria de comandos. Cisco/Juniper usam a fábrica Netmiko compartilhada com verificação de chave habilitada.


Histórico reúne sessões, relatórios, configurações exportadas, aplicações de hardening, reauditorias e erros exibidos. Clique em Atualizar histórico e selecione uma linha para abrir o artefato/log. Sessão encerrada não significa coleta aprovada: consulte o relatório técnico. O histórico local não é uma trilha externa imutável. Fechar a Central não interrompe as ferramentas já abertas; elas continuam registrando seus eventos.

Dados centrais ficam em dados/cadastro.json, dados/historico e dados/despachos. Os despachos contêm somente inventário e referências, sem senhas. Resultados próprios dos módulos continuam nas respectivas pastas.

## Atualização preservando dados

Na aba Opções → Atualização escolha um ZIP com release.json e uma pasta FORA da instalação atual. O programa valida caminhos, duplicações e hashes, cria uma nova instalação e copia inventários, políticas, projetos, logs e resultados. Código antigo não substitui o novo. A instalação anterior permanece disponível para retorno.

Feche as ferramentas antes de atualizar, evitando copiar arquivos em gravação. Depois abra CentralRefresh.exe na nova pasta. Uma falha não altera a instalação antiga e marca a extração incompleta. Os hashes verificam integridade, mas não autenticam a origem do ZIP: use um pacote confiável.

Para migrar pela primeira vez de uma versão sem atualizador: extraia a nova versão em outra pasta e use Importar dados de instalação anterior. Configurações atuais modificadas não são sobrescritas; conflitos são copiados para dados/importados para revisão. Arquivos dentro de bases não substituem o novo catálogo. Documentos salvos fora da instalação permanecem nos locais originais e não são movidos.

## Versões

A Central mostra sua versão, a versão do núcleo e a de cada módulo. O catálogo identifica corretamente FortiGate 60F 7.4.9 e 40F 7.4.12. release.json descreve a distribuição; version.json identifica cada módulo. Não copie apenas o executável: utilize a pasta completa.

## Atualização 2.1.0

Hardening ampliado com backup criptografado, SSH OTP, FortiToken, exceções, compatibilidade, espera HA, reversão aprovada e comparação de verificações. Consulte ferramentas/fortigate-hardening/LEIA-ME.md no executável, ou ../fortigate-hardening/LEIA-ME.md no código-fonte.
