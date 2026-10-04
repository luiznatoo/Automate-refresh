"""Cadastro manual e importação transacional de inventário, sem credenciais."""
import csv
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
import inventario as auditoria

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
        bar=ttk.Frame(parent);bar.grid(row=0,column=0,sticky='ew',padx=8,pady=8)
        for label,action in [('Adicionar firewall',lambda:self.open_editor(False)),('Importar CSV',self.import_csv),('Editar',lambda:self.open_editor(True)),('Remover',self.remove)]:
            ttk.Button(bar,text=label,command=action).pack(side='left',padx=(0,6))
        self.mode=tk.StringVar(value='Adicionar à lista')
        self.vars={k:tk.StringVar(value='22' if k=='porta' else '') for k in auditoria.FIELDS}
        container=ttk.Frame(parent);container.grid(row=2,column=0,sticky='nsew',padx=8);container.columnconfigure(0,weight=1);container.rowconfigure(0,weight=1)
        self.tree=ttk.Treeview(container,columns=auditoria.FIELDS,show='headings',selectmode='extended')
        for key in auditoria.FIELDS:self.tree.heading(key,text=LABELS[key]);self.tree.column(key,width=85 if key=='porta' else 170,minwidth=70,stretch=False)
        self.tree.grid(row=0,column=0,sticky='nsew')
        sy=ttk.Scrollbar(container,orient='vertical',command=self.tree.yview);sy.grid(row=0,column=1,sticky='ns')
        sx=ttk.Scrollbar(container,orient='horizontal',command=self.tree.xview);sx.grid(row=1,column=0,sticky='ew');self.tree.configure(yscrollcommand=sy.set,xscrollcommand=sx.set)
        self.tree.bind('<<TreeviewSelect>>',self.select);self.tree.bind('<Double-1>',lambda e:self.open_editor(True))
        self.count=tk.StringVar(value='0 firewalls');ttk.Label(parent,textvariable=self.count).grid(row=1,column=0,sticky='w',padx=8,pady=4)
    def open_editor(self,editing=False):
        if not self.available():return
        if editing:
            if len(self.tree.selection())!=1:messagebox.showinfo('Firewall','Selecione um firewall para editar.',parent=self.parent);return
            self.select()
        else:self.clear_fields()
        win=tk.Toplevel(self.parent);win.title('Editar firewall' if editing else 'Adicionar firewall');win.transient(self.parent.winfo_toplevel());win.grab_set();win.resizable(False,False)
        body=ttk.Frame(win,padding=18);body.pack(fill='both',expand=True)
        for i,(key,label) in enumerate([('host','IP ou DNS'),('nome','Nome (opcional)')]):
            ttk.Label(body,text=label).grid(row=2*i,column=0,sticky='w',pady=(8,2));ttk.Entry(body,textvariable=self.vars[key],width=42).grid(row=2*i+1,column=0,sticky='ew')
        extra=ttk.Frame(body)
        def toggle():
            if extra.winfo_ismapped():extra.grid_remove()
            else:extra.grid(row=5,column=0,sticky='ew',pady=6)
        ttk.Button(body,text='Conexão diferente do padrão…',command=toggle).grid(row=4,column=0,sticky='w',pady=10)
        for i,(key,label) in enumerate([('porta','Porta SSH'),('usuario','Usuário específico (opcional)')]):
            ttk.Label(extra,text=label).grid(row=i,column=0,sticky='w');ttk.Entry(extra,textvariable=self.vars[key],width=25).grid(row=i,column=1,pady=4)
        if self.vars['porta'].get()!='22' or self.vars['usuario'].get():toggle()
        def save():
            if not self.available():return
            try:
                data={k:v.get().strip() for k,v in self.vars.items()};data['nome']=data['nome'] or data['host']
                rows=list(self.data)
                if editing:rows[int(self.tree.selection()[0])]=data
                else:rows.append(data)
                self.set_rows(rows);self.clear_fields();win.destroy()
            except Exception as exc:messagebox.showerror('Firewall',str(exc),parent=win)
        ttk.Button(body,text='Salvar' if editing else 'Adicionar',command=save).grid(row=6,column=0,sticky='e',pady=(8,0))

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
