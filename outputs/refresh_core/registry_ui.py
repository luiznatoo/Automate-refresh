import copy
import csv
import tkinter as tk
from tkinter import ttk,messagebox,filedialog
from . import inventory

class Registry:
    def __init__(self,parent,path,changed):
        self.path=path;self.data=inventory.read(path);self.changed=changed
        self.window=tk.Toplevel(parent);self.window.title('Cadastro central — sem senhas');self.window.geometry('1080x670')
        tabs=ttk.Notebook(self.window);tabs.pack(fill='both',expand=True,padx=10,pady=10)
        self.editors={}
        for key,fields,title in [('units',['unidade'],'Unidades'),('groups',inventory.GROUP_FIELDS,'Grupos de credenciais'),('devices',inventory.FIELDS,'Equipamentos')]:
            frame=ttk.Frame(tabs,padding=10);tabs.add(frame,text=title)
            ttk.Label(frame,text='Grupos guardam usuário e nomes de variáveis de senha/enable; nunca digite uma senha nesses campos. Cadastre unidades e grupos antes dos equipamentos.',wraplength=950).pack(anchor='w',pady=5)
            tree=ttk.Treeview(frame,columns=fields,show='headings',height=12)
            for field in fields:tree.heading(field,text=field);tree.column(field,width=145,minwidth=80)
            tree.pack(fill='both',expand=True)
            scroll=ttk.Scrollbar(frame,orient='horizontal',command=tree.xview);scroll.pack(fill='x');tree.configure(xscrollcommand=scroll.set)
            form=ttk.Frame(frame);form.pack(fill='x',pady=10);variables={}
            for i,field in enumerate(fields):
                var=tk.StringVar(value='22' if field=='porta' else '');variables[field]=var
                ttk.Label(form,text=field).grid(row=i//3*2,column=i%3,sticky='w')
                entry=ttk.Combobox(form,textvariable=var,values=inventory.PLATFORMS,state='readonly') if field=='plataforma' else ttk.Entry(form,textvariable=var)
                entry.grid(row=i//3*2+1,column=i%3,sticky='ew',padx=4,pady=4);form.columnconfigure(i%3,weight=1)
            buttons=ttk.Frame(frame);buttons.pack(fill='x')
            for label,action in [('Adicionar','add'),('Atualizar selecionado','edit'),('Remover selecionados','remove')]:ttk.Button(buttons,text=label,command=lambda k=key,a=action:self.safe(lambda:self.modify(k,a))).pack(side='left',padx=4)
            if key=='devices':
                ttk.Button(buttons,text='Importar CSV',command=lambda:self.safe(self.import_csv)).pack(side='left',padx=4)
                ttk.Button(buttons,text='Exportar CSV',command=lambda:self.safe(self.export_csv)).pack(side='left',padx=4)
            self.editors[key]=(tree,variables)
            tree.bind('<<TreeviewSelect>>',lambda e,k=key:self.select(k))
        self.render()

    def safe(self,fn):
        try:fn()
        except (ValueError,OSError,KeyError,TypeError) as exc:messagebox.showerror('Cadastro',str(exc),parent=self.window)
    def render(self):
        for key,(tree,_) in self.editors.items():
            tree.delete(*tree.get_children())
            for i,row in enumerate(self.data[key]):tree.insert('','end',iid=str(i),values=[row] if key=='units' else list(row.get(k,'') for k in tree['columns']))
    def select(self,key):
        tree,variables=self.editors[key];selected=tree.selection()
        if not selected:return
        row=self.data[key][int(selected[0])]
        for k,var in variables.items():var.set(row if key=='units' else row[k])
    def modify(self,key,action):
        tree,variables=self.editors[key];selection=tree.selection();data=copy.deepcopy(self.data)
        row=variables['unidade'].get().strip() if key=='units' else {k:v.get().strip() for k,v in variables.items()}
        if action=='add':data[key].append(row)
        else:
            if not selection:raise ValueError('Selecione uma linha')
            if action=='edit':
                if len(selection)!=1:raise ValueError('Selecione uma linha para editar')
                index=int(selection[0]);old=data[key][index]
                if key=='units':
                    for d in data['devices']:
                        if d['unidade']==old:d['unidade']=row
                if key=='groups':
                    for d in data['devices']:
                        if d['grupo']==old['nome']:d['grupo']=row['nome']
                data[key][index]=row
            else:
                for index in sorted(map(int,selection),reverse=True):data[key].pop(index)
        inventory.save(self.path,data);self.data=data;self.render();self.changed()
    def import_csv(self):
        path=filedialog.askopenfilename(filetypes=[('CSV','*.csv')],parent=self.window)
        if not path:return
        with open(path,encoding='utf-8-sig',newline='') as f:
            first=f.readline();f.seek(0);reader=csv.DictReader(f,delimiter=';' if ';' in first else ',')
            if set(reader.fieldnames or [])!=set(inventory.FIELDS):raise ValueError('CSV: '+','.join(inventory.FIELDS))
            rows=[{k:(v or '').strip() for k,v in row.items()} for row in reader]
        data=copy.deepcopy(self.data)
        for row in rows:
            if row not in data['devices']:data['devices'].append(row)
        inventory.save(self.path,data);self.data=data;self.render();self.changed()
    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension='.csv',parent=self.window)
        if path:
            with open(path,'w',encoding='utf-8-sig',newline='') as f:
                writer=csv.DictWriter(f,fieldnames=inventory.FIELDS,delimiter=';');writer.writeheader();writer.writerows(self.data['devices'])
