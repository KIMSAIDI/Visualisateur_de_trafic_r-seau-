def ethernet(trame):
    """Renvoi une liste sous la forme de :
    - adr_MAC_Destination
    - adr_Mac_Source
    - Type"""
    list_ethernet = []
    adr_MAC_Destination = trame[0] + ":" + trame[1] + ":" + trame[2] + ":" + trame[3] + ":" + trame[4] + ":" + trame[5]
    adr_MAC_Source = trame[6] + ":" + trame[7] + ":" + trame[8] + ":" + trame[9] + ":" + trame[10] + ":" + trame[11]
    list_ethernet.append(adr_MAC_Destination)
    list_ethernet.append(adr_MAC_Source)


    return list_ethernet


def Verify_Http(trame):
    res = []
    for i in range(len(trame) - 3):
        if (trame[i] == "48" and trame[i + 1] == "54" and trame[i + 2] == "54" and trame[i + 3] == "50"):
            return True
    return False



def IP(trame):
    """Renvoi une liste sous la forme de :
    - adr_MAC_Destination       0
    - adr_Mac_Source            1

    - adr_IP_source             2
    - adr_IP_dest               3
    - Protcole                  4

    Si TCP :
        - source_port           5
        - destination_port      6
        - sequence_number       7
        - Ack_number            8
        - Flags                 9
        - len                   10
        - Window                11
        Si HTTP :
            - msg               12  """
    list_IP = ethernet(trame)

    # Adresses IP source et destination
    adr_IP_source = str(int(trame[26], 16)) + "." + str(int(trame[27], 16)) + "." + str(int(trame[28], 16)) + "." + str(int(trame[29], 16))
    adr_IP_dest = str(int(trame[30], 16)) + "." + str(int(trame[31], 16)) + "." + str(int(trame[32], 16)) + "." + str(int(trame[33], 16))
    list_IP.append(adr_IP_source)
    list_IP.append(adr_IP_dest)

    # total lenght
    total_lenght = int(trame[16] + trame[17], 16)

    # Option
    IHL_octet = int(trame[14][1], 16) * 4
    option_ip = IHL_octet - 20

    # Protcole
    protocol = trame[23]
    mssg = ''
    if protocol == '06':
        # Appel de la fonction TCP pour connaître le bon protcole
        list_info_tcp = tcp(trame, total_lenght, IHL_octet, option_ip)

        if Verify_Http(trame) and (list_info_tcp[0] == 80 or list_info_tcp[1] == 80) :
            list_IP.append('HTTP')
            # On récupère la ligne de requête
            cpt = 54
            while str(trame[cpt]) != '0d':
                version_dec = int(trame[cpt], 16)
                mssg += chr(version_dec)
                cpt += 1
        else :
            list_IP.append('TCP')

        # On ajoute les infos de tcp
        for info in list_info_tcp:
            list_IP.append(info)

    elif protocol == '11':
        protocol_str2 = 'UDP'
        list_IP.append(protocol_str2)
    else:
        print("Protocol inconnu")
        err = "protocol inconnu"
        list_IP.append(err)

    # Message si protcole = HTTP
    if list_IP[4] == 'HTTP':
        list_IP.append(mssg)

    return list_IP

def tcp(trame,  total_lenght, IHL_octet,  option_ip):
    """Renvoi les informations du protocole TCP de la couche transport dans l'ordre suivant :
     - source_port
     - destination_port
     - sequence_number
     - Ack_number
     - Flags
     - len
     - Window """
    list = []
    Source_Port = trame[34] + trame[35]
    Source_Dest = trame[36] + trame[37]
    list.append(int(Source_Port,16))
    list.append(int(Source_Dest,16))

    # Sequence Number
    Sequence_Number = trame[38] + trame[39] + trame[40] + trame[41]
    list.append(int(Sequence_Number,16)) #raw

    # Acknowledgment Number
    Acknowledgment_Number =  trame[42] + trame[43] + trame[44] + trame[45]
    list.append(int(Acknowledgment_Number,16))

    # Len
    THL_octet= int(trame[46][0], 16) * 4
    option_tcp = THL_octet - 20
    len = total_lenght - ((IHL_octet + option_ip) + (THL_octet+ option_tcp))
    # Si on a une longeur negative
    if len < 0 :
        len = 0

    Flags = trame[46] + trame[47]
    if trame[47] =='02':
        list.append('SYN')
    elif trame[47] == '10':
        list.append('ACK')
    elif trame[47] == '01':
        list.append('FIN')
    elif trame[47] == '08':
        list.append('PUSH')
    elif trame[47] == '09':
        list.append('FIN, PUSH')
    elif trame[47] == '18':
        list.append('PSH,ACK')
    elif trame[47] == '12' :
        list.append('SYN, ACK')
    elif trame[47] == '11' :
        list.append('FIN, ACK')
    elif trame[47] == '14' :
        list.append('RST, ACK')
    elif trame[47] == '1A':
        list.append('SYN, PSH, ACK')
    elif trame[47] == '1B' :
        list.append('FIN, SYN, PSH, ACK')
    elif trame[47] == '19':
        list.append('FIN,PSH,ACK')
    else:
        list.append(Flags)

    list.append(len)

    window = int(trame[48] + trame[49], 16)
    list.append(window)


    return list

