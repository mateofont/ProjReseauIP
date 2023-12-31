import tkinter as tk
from tkinter import messagebox
import ipaddress
import sqlite3
import hashlib
from PIL import Image, ImageTk
import re

#J'ai ajouté un bouton retour dans inscription, y'avaiy un buug dans inscription quand tu cliquais sur s'inscrire alors quil n'y vait rien
#dans utilisateur ou mdp ça te connectais, mtn il y a une errorbox 

# !!!!!!!!!!!!!!!!!!!!!!!!!!! TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#                                                                !                                                    !
#           TESTER AVEC IP RESERVEES                             !                        !
#           AJUSTER ESPACE ENTRE BOUTONS / EMBELLIR GUI          !
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

def is_valid_ip(ip):
    ipreserve = [
        ipaddress.ip_network('10.0.0.0/8'),  # Plage IP privée
        ipaddress.ip_network('172.16.0.0/12'),  # Plage IP privée
        ipaddress.ip_network('192.168.0.0/16'),  # Plage IP privée
    ]
    
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if pattern.match(ip):
        ip_parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in ip_parts):
            ip_res = ipaddress.IPv4Address(ip)
            if any(ip_res in reserved_range for reserved_range in ipreserve):
                # Demander à l'utilisateur s'il souhaite continuer malgré l'adresse IP réservée
                confirmation = messagebox.askokcancel("Adresse IP réservée", "L'adresse IP est réservée. Voulez-vous continuer?")
                return confirmation
            else:
                return True
        else:
            messagebox.showerror("Adresse IP invalide", "Les nombres dans l'adresse IP doivent être entre 0 et 255.")
            return False
    else:
        messagebox.showerror("Adresse IP invalide", "L'adresse IP n'est pas valide.\nVeuillez entrer une adresse IP dans un format valide.")
        return False

#def is_valid_ip(ip):
    #reserved_ranges = [
     #   ipaddress.ip_network('10.0.0.0/8'),  # Plage IP privée
      #  ipaddress.ip_network('172.16.0.0/12'),  # Plage IP privée
       # ipaddress.ip_network('192.168.0.0/16'),  # Plage IP privée
       # ]
    
#    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
 #   if pattern.match(ip):
  #      ip_parts = ip.split('.')
   #     if all(0 <= int(part) <= 255 for part in ip_parts):
    #        ip_res = ipaddress.IPv4Address(ip)
     #       if any(ip_res in reserved_range for reserved_range in reserved_ranges):
      #          messagebox.showerror("Adresse IP invalide", "L'adresse IP est réservée.")
       #         return False
        #    else:
         #       return True
        #else:
         #   messagebox.showerror("Adresse IP invalide", "Les nombres dans l'adresse IP doivent être entre 0 et 255.")
          #  return False
    #else:
     #   messagebox.showerror("Adresse IP invalide", "L'adresse IP n'est pas valide.\nVeuillez entrer une adresse IP dans un format valide.")
      #  return False

def is_valid_network(ip):
    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if pattern.match(ip):
        ip_parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in ip_parts):
            ip_res = ipaddress.IPv4Address(ip)
        else:
            messagebox.showerror("Adresse IP invalide", "Les nombres dans l'adresse IP doivent être entre 0 et 255.")
            return False
    else:
        messagebox.showerror("Adresse IP invalide", "L'adresse IP n'est pas valide.\nVeuillez entrer une adresse IP dans un format valide.")
        return False

#def is_valid_ip(ip):
   # pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    #if pattern.match(ip):
     #   ip_res = ipaddress.IPv4Address(ip)
      #  if not ip_res.is_reserved:
       #     return True
        #else:
         #   messagebox.showerror("Adresse IP invalide", "L'adresse IP est réservée.")
          #  return False
    #else:
     #   messagebox.showerror("Adresse IP invalide", "L'adresse IP n'est pas valide.\nVeuillez entrer une adresse IP dans un format valide.")
      #  return False
    
# Fonction pour valider une adresse IP
#def is_valid_ip(ip):
#    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
 #   if (pattern.match(ip)):
  #      return True
   # else:
    #    messagebox.showerror("Adresse IP invalide", "L'adresse IP n'est pas valide.\nVeuillez entrer une adresse IP dans un format valide")
     #   return False

# Fonction pour valider le masque en bits
def is_valid_mask(mask):
    if mask.isdigit():
        if 1 <= int(mask) <= 32:
            return True
        else:
            messagebox.showerror("Masque invalide", "Le masque doit être un nombre entier entre 1 et 32.")
            mask_entry.delete(0, tk.END)
            mask_to_check_entry.delete(0, tk.END)
            subnet_mask_entry.delete(0, tk.END)
            return False
    else:
        messagebox.showerror("Erreur", "Le masque doit être un nombre entier entre 1 et 32.")
        mask_entry.delete(0, tk.END)
        mask_to_check_entry.delete(0, tk.END)
        subnet_mask_entry.delete(0, tk.END)
        return False
    
# Fonction pour calculer l'adresse de réseau et de broadcast
def calculate_network_and_broadcast(ip, mask, is_subnet):
    if is_subnet:
        subnet_mask = int(sousres_mask_entry.get())
    else:
        subnet_mask = mask

    network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
    return network.network_address, network.broadcast_address

# Fonction appelée lorsque la checkbox est coché ou décoché
def on_checkbox_change():
    if subnet_checkbox_var.get():
        sousres_mask_entry.grid(row=4, column=1)
        subnet_mask_label.grid(row=4, column=0)
    else:
        sousres_mask_entry.grid_forget()
        subnet_mask_label.grid_forget()

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

#Fonction pour s'inscrire
def signin():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()
    if not new_username or not new_password:
        messagebox.showerror("Erreur", "Veuillez saisir un nom d'utilisateur et un mot de passe.")
        return
    if user_exists(new_username):
        messagebox.showerror("Erreur", "Cet utilisateur existe déjà.")
        return
    else:
        # Ajouter l'utilisateur à la base de données
        add_user(new_username, new_password)

    #login_frame.grid_forget()
    signin_frame.grid_forget()  # Masquer le cadre d'inscription
    login_frame.grid(row=0, column=0, padx=20, pady=20)

# Fonction appelée lorsque le bouton "Connexion" est cliqué
def login():
    username = username_entry.get()
    password = password_entry.get()

    if (check_password(username, password) and username!="" and password!=""):
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
root.geometry("400x300")

#Frame d'Inscription !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
signin_frame = tk.Frame(root)
tk.Label(signin_frame, text="Nom d'utilisateur:").grid(row=0, column=0)
new_username_entry = tk.Entry(signin_frame)
new_username_entry.grid(row=0, column=1)

tk.Label(signin_frame, text="Mot de passe:").grid(row=1, column=0)
new_password_entry = tk.Entry(signin_frame, show="*")
new_password_entry.grid(row=1, column=1)

inscription_button = tk.Button(signin_frame, text="S'inscrire", command=signin)
inscription_button.grid(row=2, columnspan=2)

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
    mask = mask_entry.get()
    issubnet = subnet_checkbox_var.get()
    if is_valid_ip(ip) and is_valid_mask(mask):
        mask=int(mask)
        network, broadcast = calculate_network_and_broadcast(ip, mask, issubnet)
        resbc_text.insert(tk.END, f"Adresse de réseau: {network}\n")
        resbc_text.insert(tk.END, f"Adresse de broadcast: {broadcast}\n")
    else:
        resbc_text.insert(tk.END, "Adresse IP ou masque invalide\n")

    
   

def display_check_ip_in_network():
    checkres_text.delete(1.0, tk.END)
    ip = ip_to_check_entry.get()
    network = network_entry.get()
    mask = mask_to_check_entry.get()
    if(is_valid_network(ip) and is_valid_network(network) and is_valid_mask(mask)) :
        mask=int(mask)
        if check_ip_in_network(ip, network, mask):
            checkres_text.insert(tk.END, f"{ip} appartient au réseau\n{network}/{mask}\n")
        else:
            checkres_text.insert(tk.END, f"{ip} n'appartient pas au réseau\n{network}/{mask}\n")
    else : checkres_text.insert(tk.END, "adresse IP, réseau ou masque invalide\n")

def display_subnet_info():
    infosousres_text.delete(1.0, tk.END)
    start_ip = start_ip_entry.get()
    mask = subnet_mask_entry.get()
    num_subnets = int(num_subnets_entry.get())
    hosts_per_subnet = int(hosts_per_subnet_entry.get())
    if(is_valid_network(start_ip) and is_valid_mask(mask)):
        mask=int(mask)
        subnet_info = calculate_subnet_info(start_ip, mask, num_subnets, hosts_per_subnet)

        for i, subnet in enumerate(subnet_info, 1):
            infosousres_text.insert(tk.END, f"Sous-réseau {i}:\n")
            infosousres_text.insert(tk.END, f"Adresse de réseau: {subnet['network']}\n")
            infosousres_text.insert(tk.END, f"Adresse de broadcast: {subnet['broadcast']}\n")
            infosousres_text.insert(tk.END, f"Nombre d'IP utilisables: {subnet['usable_ips']}\n\n")
    else :
        infosousres_text.insert(tk.END,("Adresse IP de départ ou masque invalide\n"))
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

#fonction retour inscription
def retour_inscription():
    new_username_entry.delete(0, tk.END)  # Efface le texte dans new_username_entry
    new_password_entry.delete(0, tk.END)
    signin_frame.grid_forget()
    login_frame.grid(row=0, column=0, padx=20, pady=20)

#fonction retour calcul
def retour_calcul():
    ip_entry.delete(0, tk.END)
    mask_entry.delete(0, tk.END)
    subnet_checkbox.deselect()
    sousres_mask_entry.delete(0, tk.END)
    subnet_mask_label.grid_forget()
    sousres_mask_entry.grid_forget()
    resbroadcast_frame.grid_forget()
    main_frame.grid(row=0, column=0, padx=20, pady=20)

#fonction retour verif
def retour_verif():
    network_entry.delete(0, tk.END)
    ip_to_check_entry.delete(0, tk.END)
    mask_to_check_entry.delete(0, tk.END)
    appartientres_frame.grid_forget()
    main_frame.grid(row=0, column=0, padx=20, pady=20)

#fonction retour info
def retour_info():
    start_ip_entry.delete(0, tk.END)
    subnet_mask_entry.delete(0, tk.END)
    num_subnets_entry.delete(0, tk.END)
    hosts_per_subnet_entry.delete(0, tk.END)
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

#bouton retour inscription
retourinscription_bouton = tk.Button(signin_frame, text="Retour", command=retour_inscription)
retourinscription_bouton.grid(row=12, column=0, columnspan=2)

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

# Ajouter la checkbox et l'entry pour le masque de sous-réseau
subnet_checkbox_var = tk.BooleanVar()
subnet_checkbox = tk.Checkbutton(resbroadcast_frame, text="Sous-réseau", variable=subnet_checkbox_var, command=on_checkbox_change)
subnet_checkbox.grid(row=3, column=0, columnspan=2)

subnet_mask_label = tk.Label(resbroadcast_frame, text="Masque du sous-réseau (en bits):")
sousres_mask_entry = tk.Entry(resbroadcast_frame)

network_broadcast_button.grid(row=5, columnspan=2)
resbc_text.grid(row=16, column=0, columnspan=2)


# Widgets pour vérifier si une adresse IP appartient à un réseau
tk.Label(appartientres_frame, text="Vérifier si IP appartient au réseau").grid(row=0, column=0, columnspan=2)
tk.Label(appartientres_frame, text="Adresse IP à vérifier:").grid(row=1, column=0)
ip_to_check_entry.grid(row=1, column=1)
tk.Label(appartientres_frame, text="Adresse du réseau:").grid(row=2, column=0)
network_entry.grid(row=2, column=1)
tk.Label(appartientres_frame, text="Masque (en bits):").grid(row=3, column=0)
mask_to_check_entry.grid(row=3, column=1)
check_ip_in_network_button.grid(row=7, columnspan=2)
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


# Masquer le Frame principal au démarrage
main_frame.grid_forget()

root.mainloop()




