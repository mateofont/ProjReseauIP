import tkinter as tk
from tkinter import messagebox
import ipaddress
import sqlite3
import hashlib

# !!!!!!!!!!!!!!!!!!!!!!!!!!! TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#                                                                !
#           AJOUTER CHECKBOX A LA PREMIERE FONCTIONNALITE        !
#           SI SOUS RESEAU ---> ENTRY POUR MASQUE DE SOUS RES    !
#           ET DONC AFFICHER ADRESSE DE SOUS RES                 !
#                                                                !
#           AJUSTER ESPACE ENTRE BOUTONS / EMBELLIR GUI          !
#                                                                !
#           AJOUTER BOUTON QUITTER SUR TOUTES LES PAGES          !
#                                                                !
#!!!!!!!!!!!!!!!!!!!!!!!!!!! TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Initialisation de la base de données SQLite3 pour stocker les mots de passe
conn = sqlite3.connect("passwords.db")
cursor = conn.cursor()

# Création de la table des utilisateurs avec des champs "username" et "password"
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                  username TEXT PRIMARY KEY,
                  password TEXT
               )''')

# Fonction pour vérifier si un utilisateur existe déjà dans la base de données
def user_exists(username):
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    return user is not None

# Fonction pour vérifier le mot de passe
def check_password(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user and user[1] == hashed_password:
        return True
    else:
        return False

# Fonction pour ajouter un utilisateur et son mot de passe à la base de données
def add_user(username, password):
    if not user_exists(username):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    else:
        print(f"L'utilisateur '{username}' existe déjà dans la base de données.")

# Fonction pour calculer l'adresse de réseau et de broadcast
def calculate_network_and_broadcast(ip, mask):
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return network.network_address, network.broadcast_address

# Fonction pour vérifier si une adresse IP appartient à un réseau
def check_ip_in_network(ip, network, mask):
    ip_obj = ipaddress.IPv4Address(ip)
    network_obj = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    return ip_obj in network_obj

# Fonction pour calculer les informations de sous-réseaux
def calculate_subnet_info(start_ip, mask, num_subnets, hosts_per_subnet):
    subnet_info = []
    current_ip = ipaddress.IPv4Address(start_ip)
    
    for _ in range(num_subnets):
        subnet = {}
        subnet['network'] = current_ip
        subnet['broadcast'] = current_ip + (2 ** (32 - mask)) - 1
        subnet['usable_ips'] = (2 ** (32 - mask)) - 2
        subnet_info.append(subnet)
        
        current_ip += (2 ** (32 - mask)) * hosts_per_subnet
    
    return subnet_info

#Fonction appelée lorsque le bouton "Inscription" est cliqué
def afficher_signin():
    login_frame.grid_forget()
    signin_frame.grid(row=0, column=0, padx=20, pady=20)

def signin():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()
    add_user(new_username, new_password)
    #login_frame.grid_forget()
    signin_frame.grid_forget()  # Masquer le cadre d'inscription
    main_frame.grid(row=0, column=0, padx=20, pady=20)

# Fonction appelée lorsque le bouton "Connexion" est cliqué
def login():
    username = username_entry.get()
    password = password_entry.get()

    if check_password(username, password):
        # Si le mot de passe est correct, activer les fonctionnalités
        login_frame.grid_forget()
        main_frame.grid(row=0, column=0, padx=20, pady=20)
    else:
        messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect")

# Fonction pour quitter l'application
def quitter_application():
    if messagebox.askokcancel("Quitter", "Voulez-vous vraiment quitter l'application?"):
        root.destroy()

# Création de la fenêtre principale
root = tk.Tk()
root.title("Gestion d'adresses IP et sous-réseaux")

#Frame d'Inscription !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
signin_frame = tk.Frame(root)
tk.Label(signin_frame, text="Nom d'utilisateur:").grid(row=0, column=0)
new_username_entry = tk.Entry(signin_frame)
new_username_entry.grid(row=0, column=1)

tk.Label(signin_frame, text="Mot de passe:").grid(row=1, column=0)
new_password_entry = tk.Entry(signin_frame, show="*")
new_password_entry.grid(row=1, column=1)

inscription_button = tk.Button(signin_frame, text="S'inscrire", command=signin)
inscription_button.grid(row=2, columnspan=1)

# Frame de connexion
login_frame = tk.Frame(root)
login_frame.grid(row=0, column=0, padx=20, pady=20)

tk.Label(login_frame, text="Nom d'utilisateur:").grid(row=0, column=0)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=0, column=1)

tk.Label(login_frame, text="Mot de passe:").grid(row=1, column=0)
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1)

login_button = tk.Button(login_frame, text="Connexion", command=login)
login_button.grid(row=2, column=0,columnspan=2)

#bouton quitter l'application
bouton_quitter = tk.Button(login_frame, text="Quitter", command=quitter_application)
bouton_quitter.grid(row=10, column=0, columnspan=2)

#bouton pour ajouter un utilisateur
signin_button = tk.Button(login_frame, text="Inscription", command= afficher_signin )
signin_button.grid(row=3, columnspan=2)

# Frame principal pour les fonctionnalités (3 boutons)
main_frame = tk.Frame(root)

#Frame pour calculer adresse de reseau et broadcast
resbroadcast_frame = tk.Frame(root)
#Frame pour verifier adresse appartient au réseau
appartientres_frame = tk.Frame(root)
# Frame pour info sur les sous rés 
infosousres_frame = tk.Frame(root)

# Fonctions pour afficher les différentes fonctionnalités
def display_network_broadcast():
    resbc_text.delete(1.0, tk.END)
    ip = ip_entry.get()
    mask = int(mask_entry.get())
    network, broadcast = calculate_network_and_broadcast(ip, mask)
    resbc_text.insert(tk.END, f"Adresse de réseau: {network}\n")
    resbc_text.insert(tk.END, f"Adresse de broadcast: {broadcast}\n")

def display_check_ip_in_network():
    checkres_text.delete(1.0, tk.END)
    ip = ip_to_check_entry.get()
    network = network_entry.get()
    mask = int(mask_to_check_entry.get())
    if check_ip_in_network(ip, network, mask):
        checkres_text.insert(tk.END, f"{ip} appartient au réseau {network}/{mask}\n")
    else:
        checkres_text.insert(tk.END, f"{ip} n'appartient pas au réseau {network}/{mask}\n")

def display_subnet_info():
    infosousres_text.delete(1.0, tk.END)
    start_ip = start_ip_entry.get()
    mask = int(subnet_mask_entry.get())
    num_subnets = int(num_subnets_entry.get())
    hosts_per_subnet = int(hosts_per_subnet_entry.get())
    subnet_info = calculate_subnet_info(start_ip, mask, num_subnets, hosts_per_subnet)
    
    for i, subnet in enumerate(subnet_info, 1):
        infosousres_text.insert(tk.END, f"Sous-réseau {i}:\n")
        infosousres_text.insert(tk.END, f"Adresse de réseau: {subnet['network']}\n")
        infosousres_text.insert(tk.END, f"Adresse de broadcast: {subnet['broadcast']}\n")
        infosousres_text.insert(tk.END, f"Nombre d'IP utilisables: {subnet['usable_ips']}\n\n")

# Widgets pour les fonctionnalités
ip_entry = tk.Entry(resbroadcast_frame)
mask_entry = tk.Entry(resbroadcast_frame)
network_entry = tk.Entry(appartientres_frame)
ip_to_check_entry = tk.Entry(appartientres_frame)
mask_to_check_entry = tk.Entry(appartientres_frame)
start_ip_entry = tk.Entry(infosousres_frame)
subnet_mask_entry = tk.Entry(infosousres_frame)
num_subnets_entry = tk.Entry(infosousres_frame)
hosts_per_subnet_entry = tk.Entry(infosousres_frame)
#main_text = tk.Text(main_frame, height=10, width=40)
resbc_text= tk.Text(resbroadcast_frame, height=5, width=40)
checkres_text = tk.Text(appartientres_frame , height=5, width=40)
infosousres_text = tk.Text(infosousres_frame , height=5, width=40)
# Boutons pour les fonctionnalités
network_broadcast_button = tk.Button(resbroadcast_frame, text="Calculer Réseau/Broadcast", command=display_network_broadcast)
check_ip_in_network_button = tk.Button(appartientres_frame, text="Vérifier IP dans le réseau", command=display_check_ip_in_network)
subnet_info_button = tk.Button(infosousres_frame, text="Informations sur les sous-réseaux", command=display_subnet_info)


#fonctions pour afficher les différents frame selon le button
def afficher_resbc() : 
    main_frame.grid_forget
    resbroadcast_frame.grid(row=0, column=0, padx=20, pady=20)

def afficher_checkres():
    main_frame.grid_forget
    appartientres_frame.grid(row=0, column=0, padx=20, pady=20)

def afficher_infosousres():
    main_frame.grid_forget
    infosousres_frame.grid(row=0, column=0, padx=20, pady=20)


#fonction déconnexion
def deconnexion():
    if messagebox.askokcancel("Déconnexion", "Voulez-vous vraiment vous déconnectez de l'application ?"):

        login_frame.grid(row=0, column=0, padx=20, pady=20)
        main_frame.grid_forget()
        # Réinitialisez les champs de nom d'utilisateur et de mot de passe si nécessaire.
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

#fonction retour calcul
def retour_calcul():
    resbroadcast_frame.grid_forget()
    main_frame.grid(row=0, column=0, padx=20, pady=20)

#fonction retour verif
def retour_verif():
    appartientres_frame.grid_forget()
    main_frame.grid(row=0, column=0, padx=20, pady=20)

#fonction retour info
def retour_info():
    infosousres_frame.grid_forget()
    main_frame.grid(row=0, column=0, padx=20, pady=20)

#placement des boutons dans la frame principale pour chaque fonctionnalité
resbc_button = tk.Button(main_frame, text = "Calculer Réseau/Broadcast", command=afficher_resbc)
checkres_button = tk.Button(main_frame, text = "Vérifier IP dans le réseau", command= afficher_checkres)
infosousres_button = tk.Button(main_frame, text = "Informations sur les sous-réseaux", command= afficher_infosousres)

resbc_button.grid(row=4,columnspan=2)
checkres_button.grid(row=6,columnspan=2)
infosousres_button.grid(row=8,columnspan=2)

#bouton Déconnexion
deconnexion_button = tk.Button(main_frame, text="Déconnexion", command=deconnexion)
deconnexion_button.grid(row=12, column=0, columnspan=2)

#bouton retour calcul
retourcalcul_bouton = tk.Button(resbroadcast_frame, text="Retour", command=retour_calcul)
retourcalcul_bouton.grid(row=12, column=0, columnspan=2)

#bouton retour verif
retourverif_bouton = tk.Button(appartientres_frame, text="Retour", command=retour_verif)
retourverif_bouton.grid(row=12, column=0, columnspan=2)

#bouton retour info
retourinfo_bouton = tk.Button(infosousres_frame, text="Retour", command=retour_info)
retourinfo_bouton.grid(row=12, column=0, columnspan=2)

# Widgets pour le calcul de l'adresse de réseau et du broadcast
tk.Label(resbroadcast_frame, text="Calculer Adresse de Réseau/Broadcast").grid(row=0, column=0, columnspan=2)
tk.Label(resbroadcast_frame, text="Adresse IP:").grid(row=1, column=0)
ip_entry.grid(row=1, column=1)
tk.Label(resbroadcast_frame, text="Masque (en bits):").grid(row=2, column=0)
mask_entry.grid(row=2, column=1)
network_broadcast_button.grid(row=3, columnspan=2)
resbc_text.grid(row=16, column=0, columnspan=2)


# Widgets pour vérifier si une adresse IP appartient à un réseau
tk.Label(appartientres_frame, text="Vérifier si IP appartient au réseau").grid(row=0, column=0, columnspan=2)
tk.Label(appartientres_frame, text="Adresse IP à vérifier:").grid(row=1, column=0)
ip_to_check_entry.grid(row=1, column=1)
tk.Label(appartientres_frame, text="Adresse du réseau:").grid(row=2, column=0)
network_entry.grid(row=2, column=1)
tk.Label(appartientres_frame, text="Masque (en bits):").grid(row=3, column=0)
mask_to_check_entry.grid(row=3, column=1)
check_ip_in_network_button.grid(row=4, columnspan=2)
checkres_text.grid(row=16, column=0, columnspan=2)

# Widgets pour obtenir des informations sur les sous-réseaux
tk.Label(infosousres_frame, text="Informations sur les sous-réseaux").grid(row=0, column=0, columnspan=2)
tk.Label(infosousres_frame, text="Adresse IP de départ:").grid(row=1, column=0)
start_ip_entry.grid(row=1, column=1)
tk.Label(infosousres_frame, text="Masque du sous-réseau (en bits):").grid(row=2, column=0)
subnet_mask_entry.grid(row=2, column=1)
tk.Label(infosousres_frame, text="Nombre de sous-réseaux:").grid(row=3, column=0)
num_subnets_entry.grid(row=3, column=1)
tk.Label(infosousres_frame, text="Hôtes par sous-réseau:").grid(row=4, column=0)
hosts_per_subnet_entry.grid(row=4, column=1)
subnet_info_button.grid(row=5, columnspan=2)
infosousres_text.grid(row=16, column=0, columnspan=2)


# Placement des widgets dans le Frame principal
#tk.Label(main_frame, text="Calculer Adresse de Réseau/Broadcast").grid(row=0, column=0, columnspan=2)
#tk.Label(main_frame, text="Adresse IP:").grid(row=1, column=0)
#ip_entry.grid(row=1, column=1)
#tk.Label(main_frame, text="Masque (en bits):").grid(row=2, column=0)
#mask_entry.grid(row=2, column=1)
#network_broadcast_button.grid(row=3, columnspan=2)

#tk.Label(main_frame, text="Vérifier si IP appartient au réseau").grid(row=4, column=0, columnspan=2)
#tk.Label(main_frame, text="Adresse IP à vérifier:").grid(row=5, column=0)
#ip_to_check_entry.grid(row=5, column=1)
#tk.Label(main_frame, text="Adresse du réseau:").grid(row=6, column=0)
#network_entry.grid(row=6, column=1)
#tk.Label(main_frame, text="Masque (en bits):").grid(row=7, column=0)
#mask_to_check_entry.grid(row=7, column=1)
#check_ip_in_network_button.grid(row=8, columnspan=2)

#tk.Label(main_frame, text="Informations sur les sous-réseaux").grid(row=9, column=0, columnspan=2)
#tk.Label(main_frame, text="Adresse IP de départ:").grid(row=10, column=0)
#start_ip_entry.grid(row=10, column=1)
#tk.Label(main_frame, text="Masque du sous-réseau (en bits):").grid(row=11, column=0)
#subnet_mask_entry.grid(row=11, column=1)
#tk.Label(main_frame, text="Nombre de sous-réseaux:").grid(row=12, column=0)
#num_subnets_entry.grid(row=12, column=1)
#tk.Label(main_frame, text="Hôtes par sous-réseau:").grid(row=13, column=0)
#hosts_per_subnet_entry.grid(row=13, column=1)
#subnet_info_button.grid(row=14, columnspan=2)

#tk.Label(main_frame, text="Résultat:").grid(row=15, column=0, columnspan=2)
#main_text.grid(row=16, column=0, columnspan=2)

# Masquer le Frame principal au démarrage
main_frame.grid_forget()

root.mainloop()




