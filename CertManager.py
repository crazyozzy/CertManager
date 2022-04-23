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


##creating key
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
def init_database(db_name):
    conn = sqlite3.connect(':memory:')
    # conn.execute('CREATE TABLE PRIVATEKEY (ID INTEGER PRIMARY KEY AUTOINCREMENT, KEY TEXT NOT NULL);')
    # conn.execute('CREATE TABLE CSR (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CSR TEXT NOT NULL, PRIVATEKEY_ID INT NOT NULL, FOREIGN KEY (PRIVATEKEY_ID) REFERENCES PRIVATEKEY(ID));')
    # conn.execute('CREATE TABLE CERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CRT TEXT NOT NULL, CSR_ID INT NOT NULL, CACERT_ID INT NOT NULL, FOREIGN KEY (CSR_ID) REFERENCES CSR(ID), FOREIGN KEY (CACERT_ID) REFERENCES CACERT(ID));')
    conn.execute('CREATE TABLE CERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CSR TEXT, PRVKEY TEXT, CRT TEXT);')
    conn.execute('CREATE TABLE CACERT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, CRT TEXT NOT NULL, SIGNED INT);')
    save_cdb(conn, db_name, bytes(getpass('Введите пароль для шифрования: '), encoding = 'utf-8'))
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
            init_database(input("Введите имя БД: "))
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
        self.put_widgets()

    def put_widgets(self):
        # Set action widgets
        self.db_select_label = tk.Label(self, text='Выберите БД')
        self.db_select = ttk.Combobox(self, values=list_db(), state='readonly')
        self.db_select_passwd_label = tk.Label(self, text='Введите пароль')
        self.db_select_passwd = tk.Entry(self, show='*')
        self.db_list_certs = tk.Button(self, text='Показать сертификаты', command=self.list_certs)

        # Set action grid
        self.db_select_label.grid(row=0, column=0)
        self.db_select.grid(row=0, column=1)
        self.db_select_passwd_label.grid(row=1, column=0)
        self.db_select_passwd.grid(row=1, column=1)
        self.db_list_certs.grid(row=2, column=0, columnspan=2)

    def list_certs(self):
        self.master.update_table(self.db_select.get(), self.db_select_passwd.get())

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
