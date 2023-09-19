import tkinter
import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

login = ctk.CTk()
login.geometry("500x350")

def connexion():
    print("Bienvenu") 


frame = ctk.CTkFrame(master=login)
frame.pack(pady=20, padx=60, fill ="both", expand=True)

label = ctk.CTkLabel(master=frame, text="Se connecter")
label.pack(pady=12, padx=10)

champ1 = ctk.CTkEntry(master=frame, placeholder_text="identifiant")
champ1.pack(pady=12)

champ2 = ctk.CTkEntry(master=frame, placeholder_text="Mots de passe", show="*")
champ2.pack(pady=12)

button = ctk.CTkButton(master=frame, text="Connexion", command=connexion)
button.pack(pady=12, padx=10)

checkbox = ctk.CTkCheckBox(master=frame, text="Se souvenir de moi")
checkbox.pack(pady=12, padx=10)

login.mainloop()


