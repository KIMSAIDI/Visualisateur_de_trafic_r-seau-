# Visualisateur de trafic réseau
Projet d'un visualisateur de trafic réseau dans le cadre d'une UE - Sorbonne Université  

Nous avons choisi de coder notre projet en Python pour sa simplicité. 
# Structure 
Le projet est consitué de cinq fichiers dont trois pour le code et deux fichiers .txt.

  - Trame.txt : fichier .txt contenant plusieurs trames écrit en hexadécimal (copié depuis      WireShark)

  - Analyse.py : 
    Le fichier est composé de deux fonctions :
    
      Verify_Hexa(trame) : La fonction prend en argument une trame (ici, écrite sur le             fichier trame.txt) et vérifie que tous les octets sont bien écrit en hexadécimal.
      
      analyse(file) : La fonction prend en arguement un fichier contenant plusieurs trames        (taille indéfini), analyse chaque trames et retourne une liste contenant plusieurs           listes des informations pertinente de chaque couches (du modèle TCP/IP).

  - Couche.py :
        Le fichier est composé de quatre fonctions :
        
        ethernet(trame) : prend en argument une trame et retourne une liste contenant les           adresses MAC source et destination des trames 
