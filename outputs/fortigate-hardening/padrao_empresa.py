"""Catálogo explícito do script fornecido, independente do transporte SSH."""
PRE='''================================================================
                       Bem-vindo!
       Todos as conexoes sao monitoradas e gravadas
Desconecte IMEDIATAMENTE se voce nao e um usuario autorizado!

                        Welcome!
          All connections are monitored and record
  Disconnect IMMEDIATELY if you are not an autorized user!
================================================================'''
POST='''================================================================
“O ACESSO NÃO AUTORIZADO A ESTE DISPOSITIVO É PROIBIDO!

Você deve ter permissão explícita e autorizada para acessar ou configurar este dispositivo.
Tentativas e ações não autorizadas para acessar ou usar este sistema podem resultar em ação disciplinar administrativa, penalidades civis e/ou criminais.
Todas as atividades realizadas neste dispositivo são registradas e monitoradas.”

================================================================

%%LAST_SUCCESSFUL_LOGIN%%
%%LAST_FAILED_LOGIN%%'''
MAP={'wan':'wan','lan1':'lan1','lan2':'lan2','lan3':'lan3','lan4':'lan4'}
# id, seção consultada, parâmetro, esperado, impacto/recomendação
RULES={
 'banner_pre':('Global','pre-login-banner','enable','Aviso antes do login; validar o fluxo de autenticação interativo.'),
 'banner_post':('Global','post-login-banner','enable','Aviso após o login; pode exigir aceite interativo.'),
 'telemetria_fds':('Global','fds-statistics','enable','Padrão da empresa: envio de estatísticas à Fortinet. Confirmar a política de compartilhamento de dados.'),
 'telemetria_rating':('Global','security-rating-result-submission','enable','Padrão da empresa: envio de resultados de security rating. Parâmetro ausente não será presumido como desabilitado.'),
 'ssh_grace':('Global','admin-ssh-grace-time','30','Tempo disponível para autenticação SSH; conferir acesso e MFA antes de aplicar.'),
 'https_redirect':('Global','admin-https-redirect','enable','Redirecionamento HTTP para HTTPS. Não substitui a remoção de acesso HTTP nas interfaces.'),
 'maintainer':('Global','admin-maintainer','disable','No 50E 6.2.16, desativa a recuperação de senha por maintainer no console. Nas versões modernas suportadas, a conta não existe.'),
 'static_ciphers':('Global','ssl-static-key-ciphers','disable','Validar compatibilidade dos clientes TLS antes de remover cifras estáticas.'),
 'dh_params':('Global','dh-params','8192','Exigência do script. Avaliar compatibilidade e custo computacional; não aplicar sem validação dos clientes.'),
 'faz_crypto':('FortiAnalyzer','enc-algorithm','high','Validar conectividade e compatibilidade do FortiAnalyzer. A coleta da configuração não comprova entrega de logs.'),
 'usb_config':('AutoInstall','auto-install-config','disable','Evitar instalação automática de configuração por mídia; revisar o procedimento de provisionamento.'),
 'usb_image':('AutoInstall','auto-install-image','disable','Evitar instalação automática de firmware por mídia; revisar o procedimento de recuperação.'),
 'event_log':('Eventos','event','enable','Habilitar eventos; verificar destino, retenção e capacidade de armazenamento.'),
 'texto_pre':('BannerPre','buffer',PRE,'Preservar o texto institucional aprovado; comparação ignora somente diferenças de espaçamento.'),
 'texto_post':('BannerPost','buffer',POST,'Preservar texto e variáveis LAST_SUCCESSFUL_LOGIN / LAST_FAILED_LOGIN.')}
for port,values in {
 'wan':{'role':'wan','arpforward':'disable','icmp-send-redirect':'disable','icmp-accept-redirect':'disable','lldp-transmission':'disable'},
 'lan1':{'role':'lan'},'lan2':{'role':'wan','icmp-send-redirect':'disable','icmp-accept-redirect':'disable','lldp-transmission':'disable'},
 'lan3':{'role':'lan'},'lan4':{'role':'lan'}}.items():
    for field,target in values.items():RULES['if_'+port+'_'+field]=('Interfaces',field,target,'Revisar mapeamento e topologia antes de modificar portas. Interface ausente não será criada.')
TITLES={k:(f'{k.split("_")[1]} — {v[1]}' if k.startswith('if_') else v[1]+' — '+v[0]) for k,v in RULES.items()}
TITLES.update(texto_pre='Texto do banner pré-login',texto_post='Texto do banner pós-login',telemetria_fds='Telemetria FDS — padrão da empresa',telemetria_rating='Envio de security rating — padrão da empresa')
EXTRA_AUTO={'ssh_grace':('admin-ssh-grace-time','30'),'https_redirect':('admin-https-redirect','enable')}

def normalize_banner(text):return ' '.join(text.replace('\r','').split())
