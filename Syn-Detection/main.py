
from utils import folder,find_the_way

path="pcaps"
files_add=find_the_way(path,'.pcap')
print(files_add)
outputfolder="FE"
folder(outputfolder)

for sayac,i in enumerate (files_add):
    print(f"{sayac+1}/{len(files_add)}-{i}")
    file_list=[i]
    for isim in file_list:

        filename=isim.replace(".pcap","_FE.csv")
        ths = open(filename, "w")
        ths.write(header)

        pkt = rdpcap(isim)
        for j in tqdm(pkt):
            ts=float(j.time) #
            try:pck_size=j.len #
            except:pck_size=0
            if j.haslayer(Ether):
                Ether_dst=j[Ether].dst#Ether_adresses.index(j[Ether].dst)+1
                Ether_src=j[Ether].src#Ether_adj[Ether].dstresses.index(j[Ether].src)+1
                Ether_type=j[Ether].type
            else:
                Ether_dst=0
                Ether_src=0
                Ether_type=0

            if j.haslayer(ARP):
                ARP_hwtype=j[ARP].hwtype
                ARP_ptype=j[ARP].ptype
                ARP_hwlen=j[ARP].hwlen
                ARP_plen=j[ARP].plen
                ARP_op=j[ARP].op
                ARP_hwsrc=j[ARP].hwsrc
                ARP_psrc=j[ARP].psrc
                ARP_hwdst=j[ARP].hwdst
                ARP_pdst=j[ARP].pdst
                ARP_hwsrc=j[ARP].hwsrc#Ether_adresses.index(j[ARP].hwsrc)+1
                ARP_psrc=j[ARP].psrc#IP_adresses.index(j[ARP].psrc)+1
                ARP_hwdst=j[ARP].hwdst#Ether_adresses.index(j[ARP].hwdst)+1
                ARP_pdst=j[ARP].pdst#IP_adresses.index(j[ARP].pdst)+1
            else:
                ARP_hwtype=0
                ARP_ptype=0
                ARP_hwlen=0
                ARP_plen=0
                ARP_op=0
                ARP_hwsrc=0
                ARP_psrc=0
                ARP_hwdst=0
                ARP_pdst=0
            if j.haslayer(LLC):
                LLC_dsap=j[LLC].dsap
                LLC_ssap=j[LLC].ssap
                LLC_ctrl=j[LLC].ctrl
            else:
                LLC_dsap=0
                LLC_ssap=0
                LLC_ctrl=0



            if j.haslayer(EAPOL):
                EAPOL_version=j[EAPOL].version
                EAPOL_type=j[EAPOL].type
                EAPOL_len=j[EAPOL].len

            else:
                EAPOL_version=0
                EAPOL_type=0
                EAPOL_len=0


            if j.haslayer(IP): #
                IP_Z = 0
                IP_MF= 0
                IP_DF= 0 #
                IP_version=j[IP].version
                IP_ihl=j[IP].ihl
                IP_tos=j[IP].tos
                IP_len=j[IP].len
                IP_id=j[IP].id
                IP_flags=j[IP].flags#

                IP_frag=j[IP].frag
                IP_ttl=j[IP].ttl
                IP_proto=j[IP].proto
                IP_chksum=j[IP].chksum


                #if j[IP].options!=0:
                IP_options=j[IP].options
                if "IPOption_Router_Alert"   in str(IP_options):
                    IP_options=1
                else:IP_options=0



                #if IP_flags not in ipf: ipf.append(IP_flags)

                if IP_flags & Z:IP_Z = 1
                if IP_flags & MF:IP_MF = 1
                if IP_flags & DF:IP_DF = 1 #
                #if "Flag" in str(IP_flags):
                    #IP_flags=str(IP_flags)
                    #temp=IP_flags.find("(")
                    #IP_flags=int(IP_flags[6:temp-1])




                IP_src=j[IP].src#IP_adresses.index(j[IP].src)+1
                IP_dst=j[IP].dst#IP_adresses.index(j[IP].dst)+1



            else:
                IP_Z = 0
                IP_MF= 0
                IP_DF= 0

                IP_version=0
                IP_ihl=0
                IP_tos=0
                IP_len=0
                IP_id=0
                IP_flags=0
                IP_frag=0
                IP_ttl=0
                IP_proto=0
                IP_chksum=0
                IP_src=0
                IP_dst=0
                IP_options=0
                IP_add_count=0

            if j.haslayer(ICMP):
                ICMP_type=j[ICMP].type
                ICMP_code=j[ICMP].code
                ICMP_chksum=j[ICMP].chksum
                ICMP_id=j[ICMP].id
                ICMP_seq=j[ICMP].seq
                ICMP_ts_ori=j[ICMP].ts_ori
                ICMP_ts_rx=j[ICMP].ts_rx
                ICMP_ts_tx=j[ICMP].ts_tx
                ICMP_gw=j[ICMP].gw
                ICMP_ptr=j[ICMP].ptr
                ICMP_reserved=j[ICMP].reserved
                ICMP_length=j[ICMP].length
                ICMP_addr_mask=j[ICMP].addr_mask
                ICMP_nexthopmtu=j[ICMP].nexthopmtu
                ICMP_unused=j[ICMP].unused
            else:
                ICMP_type=0
                ICMP_code=0
                ICMP_chksum=0
                ICMP_id=0
                ICMP_seq=0
                ICMP_ts_ori=0
                ICMP_ts_rx=0
                ICMP_ts_tx=0
                ICMP_gw=0
                ICMP_ptr=0
                ICMP_reserved=0
                ICMP_length=0
                ICMP_addr_mask=0
                ICMP_nexthopmtu=0
                ICMP_unused=0




            if j.haslayer(TCP):
                TCP_FIN = 0
                TCP_SYN = 0 #
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0 #
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0
                TCP_sport=j[TCP].sport
                TCP_dport=j[TCP].dport
                TCP_seq=j[TCP].seq
                TCP_ack=j[TCP].ack
                TCP_dataofs=j[TCP].dataofs #
                TCP_reserved=j[TCP].reserved
                TCP_flags=j[TCP].flags

                TCP_window=j[TCP].window #
                TCP_chksum=j[TCP].chksum
                TCP_urgptr=j[TCP].urgptr
                TCP_options=j[TCP].options
                TCP_options= str(TCP_options).replace(",","-")
                if TCP_options!="0":
                    TCP_options=1
                else:
                    TCP_options=0




                #if TCP_flags not in tcpf:
                    #tcpf.append(TCP_flags)
                #print(TCP_options)
                if TCP_flags & FIN:TCP_FIN = 1
                if TCP_flags & SYN:TCP_SYN = 1
                if TCP_flags & RST:TCP_RST = 1
                if TCP_flags & PSH:TCP_PSH = 1
                if TCP_flags & ACK:TCP_ACK = 1
                if TCP_flags & URG:TCP_URG = 1
                if TCP_flags & ECE:TCP_ECE = 1
                if TCP_flags & CWR:TCP_CWR = 1
                #print(TCP_flags)
                #if "Flag" in str(TCP_flags):
                    #TCP_flags=str(TCP_flags)
                    #temp=TCP_flags.find("(")
                    #TCP_flags=int(TCP_flags[6:temp-1])




            else:
                TCP_sport=0
                TCP_dport=0
                TCP_seq=0
                TCP_ack=0
                TCP_dataofs=0
                TCP_reserved=0
                TCP_flags=0
                TCP_window=0
                TCP_chksum=0
                TCP_urgptr=0
                TCP_options=0
                TCP_options=0
                TCP_FIN = 0
                TCP_SYN = 0
                TCP_RST = 0
                TCP_PSH = 0
                TCP_ACK = 0
                TCP_URG = 0
                TCP_ECE = 0
                TCP_CWR = 0


            if j.haslayer(UDP):
                UDP_sport=j[UDP].sport
                UDP_dport=j[UDP].dport
                UDP_len=j[UDP].len
                UDP_chksum=j[UDP].chksum
            else:
                UDP_sport=0
                UDP_dport=0
                UDP_len=0
                UDP_chksum=0





            if j.haslayer(DHCP):
                DHCP_options=str(j[DHCP].options)
                DHCP_options=DHCP_options.replace(",","-")
                if "message" in DHCP_options:
                    x = DHCP_options.find(")")
                    DHCP_options=int(DHCP_options[x-1])

            else:
                DHCP_options=0


            if j.haslayer(BOOTP):
                BOOTP_op=j[BOOTP].op
                BOOTP_htype=j[BOOTP].htype
                BOOTP_hlen=j[BOOTP].hlen
                BOOTP_hops=j[BOOTP].hops
                BOOTP_xid=j[BOOTP].xid
                BOOTP_secs=j[BOOTP].secs
                BOOTP_flags=j[BOOTP].flags
                #if "Flag" in str(BOOTP_flags):BOOTP_flags=str(BOOTP_flags)temp=BOOTP_flags.find("(") BOOTP_flags=int(BOOTP_flags[6:temp-1])
                BOOTP_ciaddr=j[BOOTP].ciaddr
                BOOTP_yiaddr=j[BOOTP].yiaddr
                BOOTP_siaddr=j[BOOTP].siaddr
                BOOTP_giaddr=j[BOOTP].giaddr
                BOOTP_chaddr=j[BOOTP].chaddr
                BOOTP_sname=str(j[BOOTP].sname)
                if BOOTP_sname!="0":
                    BOOTP_sname=1
                else:
                    BOOTP_sname=0
                BOOTP_file=str(j[BOOTP].file)
                if BOOTP_file!="0":
                    BOOTP_file=1
                else:
                    BOOTP_file=0

                BOOTP_options=str(j[BOOTP].options)
                BOOTP_options=BOOTP_options.replace(",","-")
                if BOOTP_options!="0":
                    BOOTP_options=1
                else:
                    BOOTP_options=0
            else:
                BOOTP_op=0
                BOOTP_htype=0
                BOOTP_hlen=0
                BOOTP_hops=0
                BOOTP_xid=0
                BOOTP_secs=0
                BOOTP_flags=0
                BOOTP_ciaddr=0
                BOOTP_yiaddr=0
                BOOTP_siaddr=0
                BOOTP_giaddr=0
                BOOTP_chaddr=0
                BOOTP_sname=0
                BOOTP_file=0
                BOOTP_options=0






            if j.haslayer(DNS):
                DNS_length=j[DNS].length
                DNS_id=j[DNS].id
                DNS_qr=j[DNS].qr
                DNS_opcode=j[DNS].opcode
                DNS_aa=j[DNS].aa
                DNS_tc=j[DNS].tc
                DNS_rd=j[DNS].rd
                DNS_ra=j[DNS].ra
                DNS_z=j[DNS].z
                DNS_ad=j[DNS].ad
                DNS_cd=j[DNS].cd
                DNS_rcode=j[DNS].rcode
                DNS_qdcount=j[DNS].qdcount
                DNS_ancount=j[DNS].ancount
                DNS_nscount=j[DNS].nscount
                DNS_arcount=j[DNS].arcount
                DNS_qd=str(j[DNS].qd).replace(",","-")
                if DNS_qd!="0":
                    DNS_qd=1
                else:
                    DNS_qd=0
                DNS_an=str(j[DNS].an).replace(",","-")
                if DNS_an!="0":
                    DNS_an=1
                else:
                    DNS_an=0
                DNS_ns=str(j[DNS].ns).replace(",","-")
                if DNS_ns!="0":
                    DNS_ns=1
                else:
                    DNS_ns=0
                DNS_ar=str(j[DNS].ar).replace(",","-")
                if DNS_ar!="0":
                    DNS_ar=1
                else:
                    DNS_ar=0
            else:
                DNS_length=0
                DNS_id=0
                DNS_qr=0
                DNS_opcode=0
                DNS_aa=0
                DNS_tc=0
                DNS_rd=0
                DNS_ra=0
                DNS_z=0
                DNS_ad=0
                DNS_cd=0
                DNS_rcode=0
                DNS_qdcount=0
                DNS_ancount=0
                DNS_nscount=0
                DNS_arcount=0
                DNS_qd=0
                DNS_an=0
                DNS_ns=0
                DNS_ar=0





            pdata=[]
            if "TCP" in j:
                pdata = (j[TCP].payload)
            if "Raw" in j:
                pdata = (j[Raw].load)
            elif "UDP" in j:
                pdata = (j[UDP].payload)
            elif "ICMP" in j:
                pdata = (j[ICMP].payload)
            pdata=list(memoryview(bytes(pdata)))

            if pdata!=[]:
                entropy=shannon(pdata)
            else:
                entropy=0
            payload_bytes=len(pdata)

            sport_class=port_class(TCP_sport+UDP_sport) #
            dport_class=port_class(TCP_dport+UDP_dport)
            sport23=port_1023(TCP_sport+UDP_sport)
            dport23=port_1023(TCP_dport+UDP_dport)
            sport_bare=TCP_sport+UDP_sport
            dport_bare=TCP_dport+UDP_dport#port_class(TCP_dport+UDP_dport)


            try:Mac=j.src
            except:Mac= j.addr1
            line=[ts, #
                  Ether_dst,
            Ether_src,
            IP_src,
            IP_dst,
            pck_size,
            Ether_type,
            LLC_dsap,
            LLC_ssap,
            LLC_ctrl,
            EAPOL_version,
            EAPOL_type,
            EAPOL_len,
            IP_version,
            IP_ihl,
            IP_tos,
            IP_len,
            IP_flags,#
            IP_Z,
            IP_MF,
            IP_id,
            IP_chksum,
            IP_DF  ,#
            IP_frag,
            IP_ttl,
            IP_proto,
            IP_options,
            ICMP_type,
            ICMP_code,
            ICMP_chksum,
            ICMP_id,
            ICMP_seq,
            ICMP_ts_ori,
            ICMP_ts_rx,
            ICMP_ts_tx,
            ICMP_ptr,
            ICMP_reserved,
            ICMP_length,
            #ICMP_addr_mask,
            ICMP_nexthopmtu,
            ICMP_unused,
            TCP_seq,
            TCP_ack,
            TCP_dataofs,#
            TCP_reserved,
            TCP_flags,
            TCP_FIN,
            TCP_SYN,#
            TCP_RST,
            TCP_PSH,
            TCP_ACK,#
            TCP_URG,
            TCP_ECE,
            TCP_CWR   ,
            TCP_window,
            TCP_chksum,
            TCP_urgptr,
            TCP_options,
            UDP_len,
            UDP_chksum,
            DHCP_options,
            BOOTP_op,
            BOOTP_htype,
            BOOTP_hlen,
            BOOTP_hops,
            BOOTP_xid,
            BOOTP_secs,
            BOOTP_flags,
            BOOTP_sname,
            BOOTP_file,
            BOOTP_options,
            DNS_length,
            DNS_id,
            DNS_qr,
            DNS_opcode,
            DNS_aa,
            DNS_tc,
            DNS_rd,
            DNS_ra,
            DNS_z,
            DNS_ad,
            DNS_cd,
            DNS_rcode,
            DNS_qdcount,
            DNS_ancount,
            DNS_nscount,
            DNS_arcount,
            sport_class,#
            dport_class,
            sport23,
            dport23,
            sport_bare,
            dport_bare,
            TCP_sport,
            TCP_dport,
            UDP_sport,
            UDP_dport,
            payload_bytes,
            entropy]

            #print(line)
            line=str(line).replace("[","")
            line=str(line).replace("]","")
            #line=str(line).replace("\',","-")
            line=str(line).replace(", ",",")
            line=str(line).replace("\'","")
            line=str(line).replace("None","0")
            if label:
                Label=df[label_count]
            else:
                Label="No_Label"
            ths.write(str(line)+f",{Label}\n")
            label_count+=1
            #kk=line.split(",")
            #print(len(kk))
            #if len(kk)==112:
            #ths.write(line+"\n")

            #else:print(line)
        name=isim.replace("\\","/")
        output=filename.replace("_FE.csv","_WS.csv")

        if " " not in name:
            command=f"tshark -r {name}  -T fields -e _ws.col.Source -e _ws.col.Destination  -e _ws.col.Protocol    -E header=y -E separator=, -E quote=d -E occurrence=f >{output}"
        else:
            command=f"tshark -r \"{name}\" -T fields -e _ws.col.Source -e _ws.col.Destination  -e _ws.col.Protocol    -E header=y -E separator=, -E quote=d -E occurrence=f >\"{output}\""
        os.system(command)
        ths.close()
    if len(file_list)>1:
        merged_csv(i,keyword)




