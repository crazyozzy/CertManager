##imports
import os
import sys

import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto, SSL
import base64
from os import getcwd
import sqlite3
import gzip
from getpass import getpass
import tkinter as tk
from tkinter import ttk


# creating key
def key_creation(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=b'\xfaz\xb5\xf2|\xa1z\xa9\xfe\xd1F@1\xaa\x8a\xc2', iterations=2048,
                     length=32, backend=default_backend())
    key = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
    return key


## encryption
def encryption(b, password):
    f = key_creation(password)
    safe = f.encrypt(b)
    return safe


## decryption
def decryption(safe, password):
    f = key_creation(password)
    b = f.decrypt(safe)
    return b


## Open encrypted database
def open_cdb(name, password):
    # f = gzip.open(getcwd() + name + '_crypted.sql.gz', 'rb')
    # safe = f.read()
    # f.close()
    password = bytes(password, encoding='utf-8')
    with open(name + '.certmanager', 'rb') as db:
        safe = db.read()

    content = decryption(safe, password)
    content = content.decode('utf-8')

    con = sqlite3.connect(':memory:')
    con.executescript(content)

    return con

## Save encrypted database
def save_cdb(con, name, password):
    # fp = gzip.open(name + '_crypted.sql.gz', 'wb')
    password = bytes(password, encoding='utf-8')
    b = b''

    for line in con.iterdump():
        b += bytes('%s\n', 'utf8') % bytes(line, 'utf8')

    b = encryption(b, password)

    with open(name + '.certmanager', 'wb') as db:
        db.write(b)
    # fp.write(b)
    # fp.close()

# Print help
def print_help():
    print('help - вывод данной справки')
    print('init - инициализировать базу данных')
    print('create csr - создать запрос CSR')
    print('show csr - вывести csr запрос')
    print('add crt - добавить файл сертификата')
    print('dump crt - вывести сертификат в файл')

# Initialize database
def init_database(db_name, password):
    conn = sqlite3.connect(':memory:')
    # conn.execute('CREATE TABLE PRIVATEKEY (ID INTEGER PRIMARY KEY AUTOINCREMENT, KEY TEXT NOT NULL);')
    # conn.execute('CREATE TABLE CSR (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CSR TEXT NOT NULL, PRIVATEKEY_ID INT NOT NULL, FOREIGN KEY (PRIVATEKEY_ID) REFERENCES PRIVATEKEY(ID));')
    # conn.execute('CREATE TABLE CERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CRT TEXT NOT NULL, CSR_ID INT NOT NULL, CACERT_ID INT NOT NULL, FOREIGN KEY (CSR_ID) REFERENCES CSR(ID), FOREIGN KEY (CACERT_ID) REFERENCES CACERT(ID));')
    conn.execute('CREATE TABLE CERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CSR TEXT, PRVKEY TEXT, CRT TEXT);')
    conn.execute('CREATE TABLE CACERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CRT TEXT NOT NULL, SIGNED INT);')
    save_cdb(conn, db_name, password)
    conn.close()

def create_prvkey(db_name, password):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    conn = open_cdb(db_name, password)
    prvkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
    conn.execute(f"INSERT INTO PRIVATEKEY (ID, KEY) VALUES (1, '{prvkey}');")
    save_cdb(conn, db_name, password)
    conn.close()

def create_csr(db_name, password):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    req = crypto.X509Req()
    cn = input("Введите CN: ")
    req.get_subject().CN = cn
    req.get_subject().C = input("Введите C: ")
    req.get_subject().ST = input("Введите ST: ")
    req.get_subject().L = input("Введите L: ")
    req.get_subject().O = input("Введите O: ")
    req.get_subject().OU = input("Введите OU: ")
    req.set_pubkey(key)
    req.sign(key, "sha256")
    prvkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode('utf-8')
    conn = open_cdb(db_name, password)
    conn.execute(f"INSERT INTO CERT (NAME, CSR, PRVKEY) VALUES ('{cn}', '{csr}', '{prvkey}');")
    save_cdb(conn, db_name, password)
    conn.close()
    print(f"Добавлен приватный ключ и CSR: {cn}")

def show_csr(db_name, password):
    conn = open_cdb(db_name, password)
    csr_id = list_csr(conn)
    print(conn.execute(f"SELECT CSR FROM CERT WHERE ID = '{csr_id}';").fetchall()[0][0])
    conn.close()

def list_csr(conn):
    print("[id]\tCN:")
    for csr in conn.execute(f"SELECT ID, NAME FROM CERT;").fetchall():
        print(f"[{csr[0]}]\t{csr[1]}")
    csr_id = int(input("Введите id CSR для добавления сертификата: "))
    return csr_id

def list_csrs(db_name, password):
    conn = open_cdb(db_name, password)
    # csrs = [["[id]", "CN:"], ]
    csrs = []
    for csr in conn.execute(f"SELECT ID, NAME FROM CERT;").fetchall():
        csrs.append([csr[0], csr[1]])
    conn.close()
    # print(csrs)
    return csrs

def add_crt(db_name, password):
    conn = open_cdb(db_name, password)
    csr_id = list_csr(conn)
    cert_name = input("Введите имя файла с сертификатом: ")
    with open(cert_name) as f_cert:
        cert = f_cert.read()
    conn.execute(f"UPDATE CERT SET CRT = '{cert}' WHERE ID = {csr_id}")
    save_cdb(conn, db_name, password)
    conn.close()

def dump_crt(db_name, password):
    conn = open_cdb(db_name, password)
    cert_id = list_csr(conn)
    cert = conn.execute(f"SELECT NAME, CRT FROM CERT WHERE ID = {cert_id}").fetchall()[0]
    with open(cert[0] + '.crt', 'w') as f_cert:
        f_cert.write(cert[1])
    print(f"Сертификат записан в файл: {cert[0] + '.crt'}")

def list_db():
    db = []
    for files in os.listdir():
        if '.certmanager' in files:
            db.append(files.split(sep='.')[0])
    return db

# def show_prvkey(db_name, password):
#     conn = open_cdb(db_name, password)
#     print(conn.execute('SELECT * FROM PRIVATEKEY').fetchall()[0][1])
#     conn.close()

def console():
    user_command = input("Введите команду: ")
    while (user_command != 'q') and (user_command != 'exit'):
        if user_command == 'help':
            print_help()
        elif user_command == 'init':
            init_database(input("Введите имя БД: "), getpass('Введите пароль для шифрования: '))
        elif user_command == 'create prvkey':
            create_prvkey(input("Введите имя БД: "),
                          bytes(getpass('Введите пароль для шифрования: '), encoding='utf-8'))
        elif user_command == 'create csr':
            create_csr(input("Введите имя БД: "), getpass('Введите пароль для шифрования: '))
        elif user_command == 'show csr':
            show_csr(input("Введите имя БД: "), bytes(getpass('Введите пароль для шифрования: '), encoding='utf-8'))
        elif user_command == 'add crt':
            add_crt(input("Введите имя БД: "), bytes(getpass('Введите пароль для шифрования: '), encoding='utf-8'))
        elif user_command == 'dump crt':
            dump_crt(input("Введите имя БД: "), bytes(getpass('Введите пароль для шифрования: '), encoding='utf-8'))
        else:
            print_help()

        user_command = input("Введите команду: ")

def gui():
    win = CertManagerApp()

    win.mainloop()


class CertManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('CertManager - Управление сертификатами')
        self.geometry("900x600")
        self.minsize(700, 500)
        self.iconphoto(False, tk.PhotoImage(file='media/main_icon.png'))
        self.actions_frame = AddAction(self)
        self.table_frame = AddTable(self)
        self.put_frames()

    def put_frames(self):
        self.actions_frame.place(relx=0, rely=0, relwidth=1, relheight=0.35)
        self.table_frame.place(relx=0, rely=0.35, relwidth=1, relheight=0.65)

    def update_table(self, db_name, password):
        # self.table_frame.destroy()
        self.table_frame.update_table(db_name, password)
        self.put_frames()


class AddAction(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self['background'] = self.master['background']
        self.selected_csrs = []

        self.db_select_label = tk.Label(self, text='Выберите БД', width=20)
        self.db_select = ttk.Combobox(self, values=list_db(), state='readonly', postcommand = self.update_db_list)
        self.db_select_passwd_label = tk.Label(self, text='Введите пароль', width=20)
        self.db_select_passwd = tk.Entry(self, show='*')
        self.db_connect = tk.Button(self, text='Подключится к БД', command=self.db_connect)
        self.db_disconnect = tk.Button(self, text='Отключится от БД', command=self.db_disconnect, state=tk.DISABLED)
        self.db_list_certs = tk.Button(self, text='Показать сертификаты', command=self.list_certs, state=tk.DISABLED)
        self.db_create = tk.Button(self, text='Создать новую БД', command=self.db_create)
        self.create_csr = tk.Button(self, text='Создать запрос сертификата CSR', command=self.export_cert, state=tk.DISABLED)
        self.import_pem = tk.Button(self, text='Импортировать открытый ключ', command=self.export_cert, state=tk.DISABLED)
        self.export_jks = tk.Button(self, text='Выгрузить сертификат в JKS', command=self.export_cert, state=tk.DISABLED)
        self.export_pem = tk.Button(self, text='Выгрузить сертификат в PEM', command=self.export_cert, state=tk.DISABLED)
        self.export_p12 = tk.Button(self, text='Выгрузить сертификат в p12', command=self.export_cert, state=tk.DISABLED)

        self.put_widgets()

    def put_widgets(self):
        # Set action grid
        self.db_select_label.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.db_select.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.db_select_passwd_label.grid(row=1, column=0, padx=5, pady=5)
        self.db_select_passwd.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.db_connect.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.db_disconnect.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        self.db_list_certs.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.db_create.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.create_csr.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        self.import_pem.grid(row=1, column=2, sticky="nsew", padx=5, pady=5)
        self.export_jks.grid(row=0, column=3, sticky="nsew", padx=5, pady=5)
        self.export_pem.grid(row=1, column=3, sticky="nsew", padx=5, pady=5)
        self.export_p12.grid(row=2, column=3, sticky="nsew", padx=5, pady=5)

    def update_db_list(self):
        self.db_select['values'] = list_db()

    def list_certs(self):
        self.master.update_table(self.db_select.get(), self.db_select_passwd.get())

    def db_connect(self):
        try:
            list_csrs(self.db_select.get(), self.db_select_passwd.get())
        except cryptography.fernet.InvalidToken:
            print('Неверный пароль')
        self.db_select['state'] = tk.DISABLED
        self.db_select_passwd['state'] = tk.DISABLED
        self.db_connect['state'] = tk.DISABLED
        self.db_create['state'] = tk.DISABLED
        self.db_disconnect['state'] = tk.NORMAL
        self.db_list_certs['state'] = tk.NORMAL
        self.create_csr['state'] = tk.NORMAL
        self.import_pem['state'] = tk.NORMAL
        self.export_jks['state'] = tk.NORMAL
        self.export_pem['state'] = tk.NORMAL
        self.export_p12['state'] = tk.NORMAL

    def db_disconnect(self):
        self.db_select['state'] = tk.NORMAL
        self.db_select_passwd['state'] = tk.NORMAL
        self.db_connect['state'] = tk.NORMAL
        self.db_create['state'] = tk.NORMAL
        self.db_disconnect['state'] = tk.DISABLED
        self.db_list_certs['state'] = tk.DISABLED
        self.create_csr['state'] = tk.DISABLED
        self.import_pem['state'] = tk.DISABLED
        self.export_jks['state'] = tk.DISABLED
        self.export_pem['state'] = tk.DISABLED
        self.export_p12['state'] = tk.DISABLED

    def db_create(self):
        db_create_windows = CreateDb(self)
        db_params = db_create_windows.create_db()
        init_database(db_params['db_name'], db_params['password'])

    def export_cert(self):
        select_csr_window = SelectCsr(self)
        self.selected_csrs = select_csr_window.select_csr()
        current_item = self.master.table_frame.table.focus()
        print(self.master.table_frame.table.item(current_item)['values'])


class AddTable(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # self['background'] = self.master['background']
        self['background'] = 'gray'
        self.put_widgets()

    def put_widgets(self):
        # Set table widgets
        self.table = ttk.Treeview(self, show='headings')
        self.table.pack(expand=tk.YES, fill=tk.BOTH)

    def update_table(self, db_name, password):
        self.table.delete(*self.table.get_children())
        self.table['columns'] = ["id", "CN"]
        for header in self.table['columns']:
            self.table.heading(header, text=header, anchor='center')
        self.table.column(self.table['columns'][0], width=35, minwidth=35, stretch=tk.NO)
        try:
            csrs = list_csrs(db_name, password)
        except cryptography.fernet.InvalidToken:
            print('Неверный пароль')
        else:
            for row in csrs:
                self.table.insert('', tk.END, values=row)
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscroll=ysb.set)
        self.table.pack(expand=tk.YES, fill=tk.BOTH)


class SelectCsr(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)

    def select_csr(self):
        self.grab_set()
        self.wait_window()
        return

class CreateDb(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.db_name_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self.db_name_label = tk.Label(self, text='Введите имя БД', width=20)
        self.db_passwd_label = tk.Label(self, text='Введите пароль')
        self.db_name = tk.Entry(self, textvariable=self.db_name_var)
        self.db_passwd = tk.Entry(self, show='*', textvariable=self.password_var)
        self.submit = tk.Button(self, text="Создать", command=self.destroy)

        self.db_name_label.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.db_passwd_label.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.db_name.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.db_passwd.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        self.submit.grid(row=2, column=0, sticky="nsew", padx=5, pady=5, columnspan=2)

    def create_db(self):
        self.grab_set()
        self.wait_window()
        return {'db_name': self.db_name_var.get(), 'password': self.password_var.get()}


# Variables
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
# HOME = os.getenv("HOME")
# now = datetime.datetime.now()
# d = now.date()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'console':
        console()
    else:
        gui()
