#!/bin/bash
#author qiuchen jiushan muyuan
#diff  netstat snmp metric 
for i in {1..3600}
    do
    echo `date`
    cat /proc/net/netstat /proc/net/snmp |  awk '(f==0) {name=$1; i=2; while ( i<=NF) {n[i] = $i; i++ }; f=1; next} (f==1){ i=2; while ( i<=NF){ printf "%s%s = %d\n", name, n[i], $i; i++}; f=0} ' | egrep -vi "= 0|icmp|InDatagrams|OutDatagrams|InSegs|OutSegs|ActiveOpens|PassiveOpens|InDelivers|InReceives|InOctets|OutOctets|OutRequests|TCPKeepAlive|TCPDelivered|TCPHPHits|TCPHPAcks|TCPPureAcks|TcpExt\:TW|TCPRcvCoalesce|TCPOrigDataSent|DelayedACKs|TCPDSACKRecv|InNoECTPkts|CurrEstab" >first_rest
    sleep 5
    cat /proc/net/netstat /proc/net/snmp |  awk '(f==0) {name=$1; i=2; while ( i<=NF) {n[i] = $i; i++ }; f=1; next} (f==1){ i=2; while ( i<=NF){ printf "%s%s = %d\n", name, n[i], $i; i++}; f=0} ' | egrep -vi "= 0|icmp|InDatagrams|OutDatagrams|InSegs|OutSegs|ActiveOpens|PassiveOpens|InDelivers|InReceives|InOctets|OutOctets|OutRequests|TCPKeepAlive|TCPDelivered|TCPHPHits|TCPHPAcks|TCPPureAcks|TcpExt\:TW|TCPRcvCoalesce|TCPOrigDataSent|DelayedACKs|TCPDSACKRecv|InNoECTPkts|CurrEstab" >second_rest 
    echo -e "Differences between two collect: \n"
    diff first_rest second_rest
    sleep 10
    done
