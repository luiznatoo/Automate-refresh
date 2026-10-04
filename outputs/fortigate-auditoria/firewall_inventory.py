"""Cadastro manual e importação transacional de inventário, sem credenciais."""
import csv
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
import auditoria

LABELS={'nome':'Nome','host':'IP / DNS','porta':'Porta SSH','usuario':'Usuário específico',
 'modelo_esperado':'Modelo esperado','versao_esperada':'Versão esperada','hostname_esperado':'Hostname esperado',
 'ha_esperado':'HA esperado','bgp_esperados':'BGP esperado (|)','vpns_esperadas':'VPNs esperadas (|)'}

def merge_devices(current,incoming,replace=False):
    incoming=auditoria.validate_devices(incoming)
    if replace:return incoming
    result=auditoria.validate_devices(current,allow_empty=True)
    by={(d['host'].lower(),d['porta']):d for d in result}
    for d in incoming:
        key=(d['host'].lower(),d['porta'])
        if key in by:
            if d!=by[key]:raise ValueError(f"{d['host']}:{d['porta']} já existe com dados diferentes. Edite o cadastro ou escolha Substituir lista.")
        else:result.append(d);by[key]=d
    return result

class Inventory:
    def __init__(self,parent,changed=lambda:None,available=lambda:True):
        self.changed=changed;self.available=available;self.parent=parent;self.data=[]
        parent.columnconfigure(0,weight=1);parent.rowconfigure(2,weight=1)
        ttk.Label(parent,text='Cadastre um firewall ou importe uma lista CSV. A auditoria usa exatamente os equipamentos desta tabela.\nNome e IP/DNS são obrigatórios. Usuário vazio utiliza o usuário padrão da aba Acesso.',wraplength=850).grid(row=0,column=0,sticky='w',padx=8,pady=8)
        bar=ttk.Frame(parent);bar.grid(row=5,column=0,sticky='ew',padx=4,pady=6)
        actions=[('Adicionar',self.add),('Atualizar selecionado',self.update),('Remover selecionados',self.remove),('Limpar campos',self.clear_fields),('Importar CSV',self.import_csv),('Exportar CSV',self.export_csv)]
        buttons=[ttk.Button(bar,text=label,command=action) for label,action in actions]
        def arrange(event=None):
            width=event.width if event else bar.winfo_width()
            unit=max(button.winfo_reqwidth()+10 for button in buttons)
            columns=max(1,width//unit)
            for i,button in enumerate(buttons):button.grid(row=i//columns,column=i%columns,sticky='w',padx=4,pady=4)
        bar.bind('<Configure>',arrange);arrange()
        self.mode=tk.StringVar(value='Adicionar à lista')
        options=ttk.Frame(parent);options.grid(row=4,column=0,sticky='ew',padx=8)
        ttk.Label(options,text='Ao importar:').pack(side='left')
        ttk.Combobox(options,textvariable=self.mode,values=['Adicionar à lista','Substituir lista'],state='readonly',width=20).pack(side='left',padx=8)
        form=ttk.LabelFrame(parent,text='Adicionar ou editar firewall',padding=8);form.grid(row=3,column=0,sticky='ew',padx=8,pady=6)
        self.vars={}
        for index,key in enumerate(auditoria.FIELDS):
            row=index//3;col=(index%3)*2
            ttk.Label(form,text=LABELS[key]).grid(row=row,column=col,sticky='w',padx=4,pady=4)
            var=tk.StringVar(value='22' if key=='porta' else '');self.vars[key]=var
            entry=ttk.Combobox(form,textvariable=var,values=['','standalone','a-p','a-a'],state='readonly',width=16) if key=='ha_esperado' else ttk.Entry(form,textvariable=var,width=16)
            entry.grid(row=row,column=col+1,sticky='ew',padx=4,pady=4);form.columnconfigure(col+1,weight=1)
        container=ttk.Frame(parent);container.grid(row=2,column=0,sticky='nsew',padx=8);container.columnconfigure(0,weight=1);container.rowconfigure(0,weight=1)
        self.tree=ttk.Treeview(container,columns=auditoria.FIELDS,show='headings',selectmode='extended')
        for key in auditoria.FIELDS:self.tree.heading(key,text=LABELS[key]);self.tree.column(key,width=85 if key=='porta' else 170,minwidth=70,stretch=False)
        self.tree.grid(row=0,column=0,sticky='nsew')
        sy=ttk.Scrollbar(container,orient='vertical',command=self.tree.yview);sy.grid(row=0,column=1,sticky='ns')
        sx=ttk.Scrollbar(container,orient='horizontal',command=self.tree.xview);sx.grid(row=1,column=0,sticky='ew');self.tree.configure(yscrollcommand=sy.set,xscrollcommand=sx.set)
        self.tree.bind('<<TreeviewSelect>>',self.select)
        self.count=tk.StringVar(value='0 firewalls');ttk.Label(parent,textvariable=self.count).grid(row=1,column=0,sticky='w',padx=8,pady=4)
    def rows(self):return auditoria.validate_devices(self.data)
    def set_rows(self,rows):
        validated=auditoria.validate_devices(rows,allow_empty=True)
        self.data=validated;self.tree.delete(*self.tree.get_children())
        for i,d in enumerate(validated):self.tree.insert('','end',iid=str(i),values=[d[k] for k in auditoria.FIELDS])
        self.count.set(f'{len(validated)} firewall(s) na lista');self.changed()
    def clear_fields(self):
        for key,var in self.vars.items():var.set('22' if key=='porta' else '')
    def select(self,event=None):
        chosen=self.tree.selection()
        if len(chosen)==1:
            for key,var in self.vars.items():var.set(str(self.data[int(chosen[0])][key]))
    def add(self):
        if not self.available():return
        try:
            self.set_rows(self.data+[{k:v.get() for k,v in self.vars.items()}]);self.clear_fields()
        except Exception as exc:messagebox.showerror('Cadastro',str(exc),parent=self.parent)
    def update(self):
        if not self.available():return
        chosen=self.tree.selection()
        if len(chosen)!=1:messagebox.showinfo('Cadastro','Selecione uma linha para atualizar.',parent=self.parent);return
        try:
            rows=list(self.data);index=int(chosen[0]);rows[index]={k:v.get() for k,v in self.vars.items()}
            self.set_rows(rows);self.tree.selection_set(str(index))
        except Exception as exc:messagebox.showerror('Cadastro',str(exc),parent=self.parent)
    def remove(self):
        if not self.available():return
        indexes={int(i) for i in self.tree.selection()}
        if indexes:self.set_rows([d for i,d in enumerate(self.data) if i not in indexes]);self.clear_fields()
    def clear(self):
        if self.available():self.set_rows([])
    def import_csv(self):
        if not self.available():return
        path=filedialog.askopenfilename(filetypes=[('Inventário CSV','*.csv')],parent=self.parent)
        if not path:return
        try:
            incoming=auditoria.inventory(path)
            self.set_rows(merge_devices(self.data,incoming,self.mode.get()=='Substituir lista'))
        except Exception as exc:messagebox.showerror('Importação',str(exc),parent=self.parent)
    def export_csv(self):
        try:rows=self.rows()
        except ValueError as exc:messagebox.showerror('Inventário',str(exc),parent=self.parent);return
        path=filedialog.asksaveasfilename(defaultextension='.csv',initialfile='firewalls.csv',filetypes=[('Inventário CSV','*.csv')],parent=self.parent)
        if not path:return
        try:
            with Path(path).open('w',encoding='utf-8-sig',newline='') as file:
                writer=csv.DictWriter(file,fieldnames=auditoria.FIELDS,delimiter=';');writer.writeheader();writer.writerows(rows)
        except OSError as exc:messagebox.showerror('Salvar lista',str(exc),parent=self.parent)
