"""Relatório operacional compacto, sem depender de modelo com dados locais."""
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
import re


def prepare_template(tables):
    from localizar import useful_rows
    book=Workbook();book.remove(book.active)
    rows=useful_rows(tables)
    pending=[]
    for row in rows:
        if row['Resultado']!='Localizado':
            pending.append({'Equipamento / dispositivo':row['Dispositivo'] or row['MAC'] or row['IP'],
                            'Pendência':row['Resultado'].replace('A revisar: ',''),
                            'Ação':'Conferir porta e VLAN nos switches; repetir a coleta se houve falhas.'})
    for category,label in [('Coleta','Switch'),('Coleta FortiGate','Firewall')]:
        for item in tables.get(category,[]):
            error=item.get('Erros','')
            if error or item.get('Tabela MAC')=='FALHA':
                pending.append({'Equipamento / dispositivo':item.get(label,''),
                                'Pendência':'Consulta incompleta',
                                'Ação':'Verificar acesso/permissões SSH e repetir. Detalhes no log da coleta.'})
    for title,data,headers,widths in [
        ('Dispositivos',rows,['Dispositivo','IP','MAC','Switch','Porta','VLAN','Resultado'],[26,28,22,26,20,22,38]),
        ('Pendências',pending,['Equipamento / dispositivo','Pendência','Ação'],[32,36,80])]:
        sheet=book.create_sheet(title);sheet.append(headers)
        for row in data:
            sheet.append([re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(row.get(k,'') or ''))[:32767] for k in headers])
        for row in sheet:
            for cell in row:
                cell.data_type='s';cell.alignment=Alignment(vertical='center',wrap_text=True)
        for cell in sheet[1]:cell.font=Font(color='FFFFFF',bold=True);cell.fill=PatternFill('solid',fgColor='203B60')
        for i,width in enumerate(widths,1):sheet.column_dimensions[get_column_letter(i)].width=width
        sheet.row_dimensions[1].height=28
        sheet.freeze_panes='A2';sheet.auto_filter.ref=sheet.dimensions
    return book
