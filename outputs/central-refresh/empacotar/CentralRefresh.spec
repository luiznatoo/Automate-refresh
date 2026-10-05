# Build with Python and all requirements available on Windows.
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, copy_metadata
root=Path(SPECPATH)
data=collect_data_files('ntc_templates')
for package in ('netmiko','ntc_templates','paramiko','openpyxl','textfsm'):
    data += copy_metadata(package)
a=Analysis([str(root/'entrada.py')],pathex=[],binaries=[],datas=data,hiddenimports=[],hookspath=[],hooksconfig={},runtime_hooks=[],excludes=[],noarchive=False)
pyz=PYZ(a.pure)
gui=EXE(pyz,a.scripts,[],exclude_binaries=True,name='CentralRefresh',debug=False,bootloader_ignore_signals=False,strip=False,upx=False,console=False)
coll=COLLECT(gui,a.binaries,a.datas,strip=False,upx=False,name='CentralRefresh')
