import pyshark
from datetime import datetime
#filtras
filter= ("ssl.handshake.extensions_server_name")
#cap interface ir laikas
cap = pyshark.LiveCapture(interface="enp0s8", display_filter=filter)
cap.sniff(timeout=0)
time = str(datetime.now().strftime("%m-%d %H:%M:%S"))

try:
#paketu tikrinimas pkt paketas cap visas paketu rinkinys
    for pkt in cap:
        #atidarom txt outputo faila
        with open("output.txt", "a") as f:
            #nurodom kokia info mus duomina si kart paketo ssl layerio handshake extension serverio vardo pavadinimas
            vrd = pkt.ssl.handshake_extensions_server_name
            #spaudinam i faila ir i ekrana
            print(pkt.ip.src+" "+pkt.eth.src_resolved+" atidare "+vrd+"   |"+time, file=f)
            print(pkt.ip.src+" "+pkt.eth.src_resolved+" atidare "+vrd+"   |"+time)
#jei pakete vardo nera paketa praleidziam
except AttributeError:
            pass
