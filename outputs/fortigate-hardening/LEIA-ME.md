# Hardening — somente o script fornecido (2.1.2)

## Usar
1. Adicione os firewalls por IP/DNS ou importe CSV. Nome é opcional no cadastro manual.
2. Informe usuário e senha SSH abaixo da lista; permanecem na sessão.
3. Clique em Verificar hardening. Se houver falha SSH, a tela informa a causa; não significa que o firewall foi verificado.
4. Na aba Correções, selecione os itens, revise os comandos e aprove. A senha para criptografar backups é pedida apenas na primeira aplicação da sessão.

## Escopo
São 31 controles derivados exclusivamente do script enviado: banners e textos pré/pós-login; funções das portas wan/lan1/lan2/lan3/lan4; arpforward, redirects ICMP e LLDP nas portas indicadas; admintimeout; FDS; security-rating; SSH grace; redirecionamento HTTPS; TLS; duração do bloqueio administrativo; criptografia FortiAnalyzer; maintainer; cifras estáticas; DH; NTP; instalação automática por mídia e eventos.

Removidos: limite de tentativas, strong-crypto, HTTP/Telnet, administração WAN, trusted hosts, MFA administrativo, política de senha e SNMP. Esses controles não aparecem nem geram correções, mesmo após importar uma política antiga. Também não são feitas consultas de administradores, senha, SNMP, tokens ou SMTP.

Mantidas somente consultas auxiliares de identidade, HA e sessão SSH, necessárias para executar com segurança. A opção SSH com OTP em Opções avançadas serve para autenticação da conexão, não para auditar ou configurar MFA.

Maintainer permanece Não aplicável nas versões suportadas, pois foi removido do FortiOS. Interfaces ausentes não são criadas; confira o mapeamento em Opções avançadas. Ausência de parâmetro ou falta de permissão não equivale a conformidade.

## Erro de autenticação
Autenticação SSH recusada significa que a conexão não foi autenticada e nenhum controle foi consultado. Confira usuário/senha, a permissão da conta para SSH e se o acesso exige OTP. Não envie sua senha por chat. Uma nova tentativa só ocorre quando você manda verificar novamente.

## Aplicação e recuperação
O plano exige revisão/aprovação, identidade e estado inalterados. Antes de aplicar, é feito backup SCP sys_config criptografado com senha de 12+ caracteres. admin-scp e permissão de backup devem estar disponíveis; falha no backup bloqueia alterações. Não é habilitado silenciosamente.

O diário registra aplicação e reauditoria independente. Falhas interrompem o lote. Há espera limitada para sincronismo HA. Histórico, comparação, exportação do backup e reversão aprovada ficam em Opções avançadas. Restauração completa é manual, conforme o procedimento junto ao backup, e pode reiniciar o equipamento. Guarde a senha do backup para recuperar o arquivo.

Nenhuma configuração é aplicada durante a verificação. Os testes de desenvolvimento são locais/simulados; valide em piloto antes do lote.


## Correção 2.1.3

No 60F, nomes padrão ausentes recebem correspondência sugerida por nome: wan → wan1, lan1 → internal (ou internal1), lan2 → wan2, lan3 → internal3, lan4 → internal4. São usados apenas destinos existentes e distintos; mapeamentos personalizados são preservados. A correspondência não comprova a topologia física: os nomes reais aparecem nos resultados e no plano de aprovação para conferência. Nenhuma porta é criada.

security-rating-result-submission foi removido no FortiOS 7.4.4. Nas versões suportadas 7.4.9/7.4.12, sua ausência é Não aplicável, não Conforme nem falha de consulta. A automação não envia o comando removido.
Referência: https://community.fortinet.com/fortigate-3/technical-tip-how-to-optimize-memory-consumption-for-smaller-fortigates-94683

### FortiGate 50E — FortiOS 6.2.16

Perfil identificado automaticamente pela coleta, sem campos adicionais. Mantém os 31 controles do script e o fluxo de aprovação, backup e verificação posterior. Campos ausentes continuam pendentes, sem presumir valores. Maintainer e security-rating são verificados nesta versão; desativar maintainer impede a recuperação de senha por essa conta no console.

Quando wan não existir, usa wan1 se disponível. Portas lan1–lan4 existentes e mapeamentos personalizados são preservados, inclusive lan2. Confira os destinos no plano antes de aprovar. Outros firmwares do 50E não estão habilitados.

Referência: https://docs.fortinet.com/document/fortigate/6.2.16/cli-reference/339914554/config-system-global
