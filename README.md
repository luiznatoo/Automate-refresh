# Central Refresh

Ferramentas desktop em Python para auditoria e hardening FortiGate, mapeamento de switches, localização de dispositivos, comparação pré/pós-RDM e geração de configurações.

Versão inicial do histórico Git: **2.1.6**. O histórico anterior não está disponível como commits.

## Executar no Windows

Requer Python com Tkinter (validado localmente com Python 3.14).

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe outputs/central-refresh/central.py
```

## Arquivos privados necessários

Este repositório contém código, documentação e testes. Não contém configurações reais, senhas/valores ENC, inventários, relatórios, executáveis ou bases da empresa.

Para utilizar as ferramentas que dependem deles, copie de sua instalação confiável, localmente:

- FortiGate: pasta `bases` completa para `outputs/fortigate-config/bases` (configurações, catálogo e perfis de operadoras).
- FortiSwitch: pasta `bases` completa para `outputs/fortiswitch-config/bases`.
- Mapeamento: `modelo_fixo.xlsx` para `outputs/switch-mapper`.
- Localizador: `modelo_correspondencia.xlsx` para `outputs/localizador-mac`.
- RDM: `modelo_comparativo.xlsx` para `outputs/fortigate-rdm`.

Cadastre equipamentos na interface ou importe CSV local. Esses arquivos são ignorados pelo Git. Os geradores requerem as bases locais para abrir. Não publique os ZIPs antigos: eles incluem bases privadas. As instruções dos módulos que mencionam bases incorporadas referem-se à instalação local completa.

## Testes sem equipamentos

```powershell
python -m unittest discover -s work/hardening-script-tests -v
python -m unittest discover -s work/central-tests -v
```

As suítes incluídas exercitam o núcleo e o escopo atual do hardening; não representam cobertura completa de todos os módulos nem homologação em hardware.

## Fluxo Git

`main` mantém a versão estável. Para alterações, crie `feature/nome` ou `fix/nome`, execute os testes e abra um pull request. Atualize `CHANGELOG.md`, a versão do núcleo e a dos módulos modificados antes de uma entrega. Tags `vX.Y.Z` identificam versões: correções incrementam Z, funcionalidades compatíveis Y e mudanças incompatíveis X.

O primeiro marco é `v2.1.6`. Executáveis devem ser gerados e revisados separadamente, sem dados privados, antes de publicação em Releases. Os arquivos em `outputs/central-refresh/empacotar` são a entrada e especificação PyInstaller; a montagem portátil completa também depende dos recursos locais.

Os valores de exemplo do gerador FortiSwitch foram substituídos por endereços de documentação e nomes genéricos. Revise-os na interface antes de gerar configurações.
