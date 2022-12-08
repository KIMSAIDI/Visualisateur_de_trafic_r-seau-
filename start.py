from tkinter import *
from tkinter import ttk
from analyse import analyse
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showerror, showwarning, showinfo
import tkinter as tk
import random
import os


# fonction ecriture fichier
def Write(texte):
    with open("diagramme.txt", "a+") as file:
        file.write(texte)


def Affichage(liste_trames):
    # Creation de ma fenêtre
    window = tk.Tk()
    window.title("Visualisateur de trafic réseau")
    window.geometry("1050x580")
    window.minsize(780, 660)

    # Creation d'un tableau de données
    tree = ttk.Treeview(window, columns=(1, 2, 3, 4), height=20, show="headings")
    tree.pack()

    # Headings
    tree.heading(1, text="Numéro")
    tree.column('#1', width =100, minwidth=60)
    tree.heading(2, text="Source")
    tree.column('#2', width=300, minwidth=100)
    tree.heading(3, text="Destination")
    tree.column('#3', width=300, minwidth=100)
    tree.heading(4, text="Protocole")
    tree.column('#4', width=300, minwidth=100)

    liste_gf = []
    # Pour permettre de ranger toute les trames
    color = 0
    # color : tag
    liste_doublon = []
    # numérotation
    num = 1
    t = 0
    for t in range(len(liste_trames)):

        # On verifie que l'on à pas deja traité ce couple d'adresse
        if (liste_trames[t][2], liste_trames[t][3]) not in liste_doublon:
            # On range notre couple d'adresse source et destination dans une liste a qui on adresse une couleur
            liste_adr = [liste_trames[t][2], liste_trames[t][3]]
            # On definit notre couleur pour ce nouvel echange
            tree.tag_configure(color, background="#"+''.join([random.choice('0123456789ABCDEF') for j in range(6)]))

            for t2 in range(len(liste_trames)):

                # Si l'adresse courante (source et destination) est égale a notrec couple
                if liste_trames[t2][2] in liste_adr and liste_trames[t2][3] in liste_adr:
                    tree.insert('', 'end', values=(num, liste_trames[t2][2], liste_trames[t2][3], liste_trames[t2][4]),
                                tags=color)
                    liste_gf.append(liste_trames[t2])
                    num += 1

            # On enregistre le couple (adr1, adr2) et (adr2, adr1) dans une liste pour eviter les doublons
            liste_doublon.append((liste_trames[t][2], liste_trames[t][3]))
            liste_doublon.append((liste_trames[t][3], liste_trames[t][2]))
            # On change notre tag
            color += 1

    # Item selected
    def item_selected(event):
        for selected_item in tree.selection():
            item = tree.item(selected_item)
            record = item['values']
            # Indique l'indice de la ligne selectionné
            indice = int(selected_item[1:], 16)
            # pour eviter un index out of range on s'occupe de la trame ARP en premier
            if liste_gf[indice - 1][4] == 'TCP' or liste_gf[indice - 1][4] == 'HTTP':
                Graph_flow(indice, liste_gf)
            else:
                boutton_erreur()
        return

    tree.bind('<<TreeviewSelect>>', item_selected)
    tree.grid(row=0, column=0, sticky='nsew')

    # Scrolleur
    scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='ns')

    # afficher
    window.mainloop()


# Boutton d'erreur
def boutton_erreur():
    showerror(title='Erreur', message="Le protocole n'est pas pris en compte par le visualisateur")


# Graph Flow
def Graph_flow(indice, liste_gf):
    res_fichier = "=========================================================================================================" + "\n"

    root = Toplevel()
    root.title('Graph flow')
    root.geometry("1150x600")
    root.minsize(630, 580)

    Scroll = tk.Scrollbar(root)
    text = Text(root, height=1000, width=130)
    Scroll.pack(side=tk.RIGHT, fill=tk.Y)
    text.pack(side=tk.LEFT, fill=tk.Y)
    Scroll.config(command=text.yview)
    text.config(yscrollcommand=Scroll.set)

    text.pack(expand=YES)

    # couleur
    text.tag_config("neutre", background="lavenderblush")
    text.tag_config("red", background="tomato")

    adr_ip_src = liste_gf[indice - 1][2]
    adr_ip_dst = liste_gf[indice - 1][3]
    port_1 = str(liste_gf[indice - 1][5])
    port_2 = str(liste_gf[indice - 1][6])

    text.insert(1.0, adr_ip_dst + "\n")
    text.insert(1.0, adr_ip_src + "\t\t\t\t\t\t\t\t\t\t\t\t\t\t  ")

    res_fichier = adr_ip_src + "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t " + adr_ip_dst + "\n\n"

    ligne = 2.0

    # La fonction renvoie les commentaires associées au bon protocole
    def comment(trame):
        protcol = trame[4]
        comment = ''
        if protcol == 'TCP':
            comment += protcol + ': '
            # ports
            comment += str(trame[5]) + "->" + str(trame[6])
            # sequence number
            comment += '\t\tSeq=' + str(trame[7])
            # acknowledgment number
            comment += '\t\t\t\t\tAck=' + str(trame[8])
            # flags
            comment += '\t\t[' + trame[9] + ']'
            # window
            comment += "\t\tWin=" + str(trame[11])
            # len
            comment += "\t\tLen=" + str(trame[10])
        elif protcol == 'HTTP':
            comment += protcol + ': '
            # msg
            comment += trame[12]
        return comment

    for trame in liste_gf:
        # Commentaire
        if trame[2] == adr_ip_src and trame[3] == adr_ip_dst or trame[2] == adr_ip_dst and trame[3] == adr_ip_src:
            if trame == liste_gf[indice - 1] :
                text.insert(ligne, "                  " + comment(trame) + "\n", 'red')
                res_fichier += "                  " + comment(trame) + "\n"
            else:
                text.insert(ligne, "                  " + comment(trame) + "\n", 'neutre')
                res_fichier += "                  " + comment(trame) + "\n"

        # si notre trame courante est égale a notre adr IP : elle est source
        if trame[2] == adr_ip_src and trame[3] == adr_ip_dst:
            text.insert(ligne + 1,
                        port_1 + "  -------------------------------------------------------------------------------------------------------------------->  " + port_2 + "\n\n",
                        'neutre')
            res_fichier += port_1 + "  ------------------------------------------------------------------------------------------------------------------------------------------------->  " + port_2 + "\n"

        # si l'adr IP source de trame est égale a notre adr IP dest : l'adr ip est dest
        elif trame[2] == adr_ip_dst and trame[3] == adr_ip_src:
            # On vérifie que si l'adresse de destination ou source est broadcast :
            text.insert(ligne + 1,
                        port_1 + "  <--------------------------------------------------------------------------------------------------------------------  " + port_2 + "\n\n",
                        'neutre')
            res_fichier += port_1 + "   <-------------------------------------------------------------------------------------------------------------------------------------------------  " + port_2 + "\n"
        ligne += 2
    res_fichier += "\n\n==================================================================================================================================================================" + "\n\n"
    Write(res_fichier)
    return


# Filtre
def Filtre() :
    print("Avant de procéder à la visualisation des trames,")
    rep = ''
    while rep != "Quitter" and rep != "quitter" :

        rep = input("Voulez vous appliquer un filtre ? Oui/Non/Quitter :  ")

        liste_ip = []
        liste_protocole = []
        liste_port = []
        for element in liste_trames:
            liste_ip.append(element[2])
            liste_ip.append(element[3])
            liste_protocole.append(element[4])
            liste_port.append(element[5])
            liste_port.append(element[6])

        liste_ip = list(set(liste_ip))
        liste_port = list(set(liste_port))
        liste_protocole = list(set(liste_protocole))

        while (rep != "Oui" and rep != "Non" and rep != "oui" and rep != "non" and rep != "quitter" and rep != "Quitter"):
            rep = input("Voulez-vous appliquer un filtre ? Oui/Non :  ")
        if (rep == "Non" or rep == "non"):
            Affichage(liste_trames)
        if (rep == "Oui" or rep == "oui"):
            liste_res = []
            print("Voici la liste des adresses IP disponibles :\n")
            # On affiche notre liste de d'adresse
            for adr in liste_ip :
                print(adr)
            rep1 = input("Voulez-vous appliquer un filtre sur les adresses  ? Oui/Non :  ")
            while (rep1 != "Oui" and rep1 != "Non" and rep1 != "oui" and rep1 != "non"):
                rep1 = input("Voulez vous appliquer un filtre sur les adresses  ? Oui/Non :  ")
            if (rep1 == "Oui" or rep1 == "oui"):
                adr1 = input("Entrez une adresse IP :")
                while (adr1 not in liste_ip):
                    print("L'adresse IP n'est pas valide")
                    adr1 = input("Entrez une adresse IP : ")
                for element in liste_trames:
                    if ((element[2] == adr1) or (element[3] == adr1)):
                        liste_res.append(element)
            if (rep1 == "Oui" or rep1 == "oui"):
                print("Voici la liste des protocoles disponibles :\n")
                liste_protocole2 = []
                for element in liste_res:
                    liste_protocole2.append(element[4])
                liste_protocole2 = list(set(liste_protocole2))
                print(liste_protocole2)
            else:
                print("Voici la liste des protocoles disponibles :\n")
                print(liste_protocole)
            rep2 = input("Voulez-vous appliquer un filtre sur le protocole  ? Oui/Non :  ")
            while (rep2 != "Oui" and rep2 != "Non" and rep2 != "oui" and rep2 != "non"):
                rep2 = input("Voulez-vous appliquer un filtre sur le protocole  ? Oui/Non :  ")
            if (rep2 == "Oui" or rep2 == "oui"):
                if (rep1 == "Oui" or rep1 == "oui"):
                    prot1 = input("Entrez un protocole : ")
                    while (prot1 not in liste_protocole2):
                        print("Le protocole n'est pas valide")
                        prot1 = input("Entrez un protocole : ")
                    for element in liste_res:
                        if (element[4] != prot1):
                            liste_res.remove(element)
                else:
                    prot1 = input("Entrez un protocole : ")
                    while (prot1 not in liste_protocole):
                        print("Le protocole n'est pas valide")
                        prot1 = input("Entrez un protocole : ")
                    for element in liste_trames:
                        if (element[4] == prot1):
                            liste_res.append(element)

            if (rep1 == "Non" and rep2 == "Non") or (rep1 == "non" and rep2 == "non"):
                print("Voici la liste des ports :\n")
                print(liste_port)
            else:
                print("Voici la liste des ports :\n")
                liste_port2 = []
                for element in liste_res:
                    liste_port2.append(element[5])
                    liste_port2.append(element[6])
                    liste_port2 = list(set(liste_port2))
                print(liste_port2)

            rep3 = input("Voulez-vous appliquer un filtre sur les ports ? Oui/Non :  ")
            while (rep3 != "Oui" and rep3 != "Non" and rep3 != "oui" and rep3 != "non"):
                rep3 = input("Voulez-vous appliquer un filtre sur les ports ? Oui/Non :  ")
            if (rep3 == "Oui" or rep3 == "oui"):
                if (rep1 == "Non" and rep2 == "Non") or (rep1 == "non" and rep2 == "non"):
                    port = input("Entrez un port : ")
                    while (int(port) not in liste_port):
                        print("Le port n'est pas valide !")
                        port = input("Entrez un port : ")
                    for element in liste_trames:
                        if (element[5] == int(port) or element[6] == int(port)):
                            liste_res.append(element)
                else:
                    port = input("Entrez un port : ")
                    while (int(port) not in liste_port2):
                        print("Le port n'est pas valide")
                        port = input("Entrez un port : ")
                    for element in liste_res:
                        if ((element[5] != int(port)) and (element[6] != int(port))):
                            liste_res.remove(element)
            Affichage(liste_res)

    print("Si une fenêtre Graph Flow à été ouverte celle-ci est enregistré dans le fichier datagramme.txt")
    print("\nMerci d'avoir utilisé notre Visualisateur de trafic réseau !")
    return



# On demande le nom du fichier contenant les trames
print("\n\t\t\t~~~~~~~~~~~~~~~~~~Bienvenue dans le projet Visualisateur de trafic réseau SpathiShark (S.S)~~~~~~~~~~~~~~~~~~\n")
nom_fichier = input("Veuillez rentrer le nom du fichier contenant les trames : ")
while not os.path.exists(nom_fichier):
    print("Erreur de nom du fichier")
    nom_fichier = input("Nom fichier contenant les trames : ")
liste_trames = analyse(nom_fichier)
Filtre()
