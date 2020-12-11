import socket
import json
import sqlite3
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import traceback
import sys

dbname = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
dbconn = sqlite3.connect(dbname, check_same_thread=False)
cursor = dbconn.cursor()
usertable: str = """CREATE TABLE IF NOT EXISTS user (
                    id_u INTEGER PRIMARY KEY,
                    username TEXT,
                    ipk TEXT,
                    spk TEXT,
                    efk TEXT,
                    opk TEXT
                );"""
cursor.execute(usertable, ())
dbconn.commit()

def insertar_usuario(usuario: tuple):
    query = """INSERT INTO user
                (username, ipk, spk, efk, opk)
                values
                (?, ?, ?, ?, ?)
            """
    cursor.execute(query, usuario)
    dbconn.commit()
    return cursor.lastrowid


def select_usuario(usuario: str):
    query = """Select * from user 
                where username = ?
            """
    cursor.execute(query, (usuario, ))
    dbconn.commit()
    return cursor.fetchall()


HOST = '127.0.0.1'  # La dirección IP del host del socket
PORT = 8090        # Port to listen on (non-privileged ports are > 1023)

users={}

def atender_usuario(conn, addr):
    while True:
        print("waiting again")
        ok = {"command": "confirm"}
        data = conn.recv(1024)  # Recibir mensaje
        info = json.loads(data.decode("utf8"))
        print("just received", info)
        if info["command"] == "auth":
            print("Auth section")
            try:
                print("Trying")
                id = insertar_usuario(
                    (
                        info["user"],
                        info["IPK"],
                        info["SPK"],
                        info["EFK"],
                        info["OPK"]
                    )
                )
                print("stored")
                users[info["user"]] = {"id": id, "conn": conn}
                print("saved")
            except Exception as exception:
                print("Error")
                traceback.print_exc()
            print("tried finished")
        if info["command"] == "connect":
            try:
                user = select_usuario(info["recipient"])
                if len(user) > 0:
                    ok["command"] = "userkeys"
                    ok["username"] = user[0][1]
                    ok["IPK"] = user[0][2]
                    ok["SPK"] = user[0][3]
                    ok["EFK"] = user[0][4]
                    ok["OPK"] = user[0][5]
                    conn.sendall(json.dumps(ok).encode("utf8"))
                print("select usuario", select_usuario(info["recipient"]))
                response = json.loads((conn.recv(1024)).decode("utf8"))
                ruser = select_usuario(response["from"])
                ok["command"] = "r3xdh"
                ok["username"] = ruser[0][1]
                ok["IPK"] = ruser[0][2]
                ok["SPK"] = ruser[0][3]
                ok["EFK"] = ruser[0][4]
                ok["OPK"] = ruser[0][5]
                users[response["to"]]["conn"].sendall(json.dumps(ok).encode("utf8"))
            except Exception:
                traceback.print_exc()
        conn.sendall(json.dumps(ok).encode("utf8"))  # Responder mensaje


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT)) #Iniciar el socket
    s.listen() #Comenzar a escuchar
    with ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            conn, addr = s.accept() #Aceptar peticion de conexión
            executor.submit(atender_usuario, conn, addr)
        # conn.shutdown(0)
        # conn.close()