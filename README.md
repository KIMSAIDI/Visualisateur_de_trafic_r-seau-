# Visualisateur de trafic réseau
Projet d'un visualisateur de trafic réseau dans le cadre d'une UE - Sorbonne Université  

Nous avons choisi de coder notre projet en Python pour sa simplicité. 
# Structure 
Le projet est consitué de cinq fichiers dont trois pour le code et deux fichiers .txt.

  - Trame.txt : fichier .txt contenant plusieurs trames écrit en hexadécimal (copié depuis WireShark)

  - Analyse.py : 
    Le fichier est composé de deux fonctions et sa fonction principal est d'analyser toute les trames qui se trouve dans le fichier.txt
    
    Verify_Hexa(trame) : La fonction prend en argument une trame (ici, écrite sur le fichier trame.txt) et vérifie que tous les octets sont bien écrit en hexadécimal.
      
    analyse(file) : La fonction prend en arguement un fichier contenant plusieurs trames (taille indéfini), analyse chaque trames et retourne une liste contenant plusieurs listes des informations pertinente de chaque couches (du modèle TCP/IP).

  - Couche.py :
       
    Le fichier est composé de quatre fonctions et son rôle principal est de capturer les informations importante de chaque couches.
        
    ethernet(trame) : prend en argument une trame et retourne une liste contenant les adresses MAC source et destination des trames 

    IP(trame) : prend en arguement une trame, appel la fonction ethernet(trame), ajoute à la liste (retourné par ethernet) les informations pertinentes de la couche IP et retourne cette liste.
    
    tcp(trame, total_lenght, IHL_octet, option_ip) : prend en argument une trame et ses champs (dans l'entête IP)  total lenght, IHL et la taille des options IP afin de calculer la longueur des data en octet.
    
    Verify_Http(trame):  prend une trame en argument et verifie si la trame est une requête HTTP
    
    
  - Start.py : 
      
      Le fichier est le plus important de notre projet. Ce fichier permet d'afficher l'interface graphique.
      
      Affichage(liste_trames) : Cette fonction prend en arguement la liste des trames renvoyé par la fonction analyse et affiche dans un tableau l'adresse IP source, destination et le protocol associé à chaque trame. Toutes les communications (entre deux machines) sont delimités par une couleur, choisi aléatoirement. 
      
      item_selected(event) : retourne l'indice de la ligne selectionné dans le tableau. Si le protocole n'est pas pris en compte par notre visualisateur, un message d'erreur s'affichera. 
      
      Graph_Flow(indice, liste_gf) : Cette fonction renvoie la fenêtre de notre visualisateur en fonction de la ligne selectionné. Ainsi, dans une communication (separé par couleur) peut importe la ligne selectionné, une fenêtre s'ouvre et montre les flux échangés entre ces deux machines. 
      
      Filtre() : La fonction permet de filtrer les trames selon les adresses IP, les protcoles et les ports parmis la liste des trames renvoyé par analyse(file).
      
   - diagramme.txt : 
     Dès qu'une ligne est selectionné, la visualisation de ces flux sont copiés dans le fichier diagramme.txt afin de pouvoir relire plus facile les échanges entre deux machines.
      
      
      
      
     
      
      
      
    
