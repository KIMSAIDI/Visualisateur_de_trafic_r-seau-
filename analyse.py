from couche import IP

def Verify_Hexa(trame):
    "verifie si toutes les valeurs sont hexadécimales"
    res = True
    hexa = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f', 'A', 'B', 'C', 'D', 'E', 'F']
    for valeur in trame :
        if(valeur[0] not in hexa or valeur[1] not in hexa):
            res = False
    if not(res) :
        print("\nLa trame n'est pas valide !")
    return res



def analyse(file):
    """Renvoi une liste sous la forme de :
    - adr_MAC_Destination
    - adr_Mac_Source

    - adr_IP_source
    - adr_IP_dest
    - Protcole

    Si TCP :
        - source_port
        - destination_port
        - sequence_number
        - Ack_number
        - Flags
        - len
        - Window
        Si HTTP :
            - msg                 """
    with open(file, "r+") as file:
        lines = [l for l in (line.strip() for line in file) if l]  # retire les lignes vides
        ListeTrames = []
        list_informations_trame = []
        list_trame = []
        for index in range(len(lines)):
            lines[index] = lines[index].strip()  # on retire les espaces du début et de la fin
            splittedLine = lines[index].split("   ")  # on sépare l'offset de la trame
            ligneTrame = splittedLine[1].split(" ")  # on sépare les élements de notre trame
            offset = int(splittedLine[0], 16)
            if index + 1 == len(lines):  # Cas de la dernière ligne où il n'y a pas de suivant
                nextoffset = 0
            else:
                nextoffset = int(lines[index + 1].split("   ")[0], 16)  # on prend l'offset suivant
            if (offset == 0):
                trame = []
                trameFini = True
            if (nextoffset != 0):
                trame.extend(ligneTrame)
                trameFini = False
            if (nextoffset == 0):
                trame.extend(ligneTrame)
                trameFini = True
            if (trameFini):
                if(Verify_Hexa(trame)):
                    # On récupère son adresse IP src et dest
                    list_ = IP(trame)
                    # On récupère ses données dans TCP
                    ListeTrames.append(trame)
                    list_trame.append(list_)
                    list_ = []

    print("==========================================================================")
    #print("\t\t\t--------------------------------------------------------------------------\n")
    print("\t                        Projet S.S \n")
    print("==========================================================================")
    #print("\t\t\t--------------------------------------------------------------------------\n")
    print("Nous avons analyser ", len(list_trame), " traces valides présente dans le fichier \n")

    return list_trame

