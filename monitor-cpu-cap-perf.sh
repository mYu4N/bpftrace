#!/bin/bash
# auth muyuan.ymy
# when the cpu usage of the specific process is greater than the cpu_threshold ,
# it will trigger perf to capture kernel trace for 10s . 
# cat /dev/zero >/dev/null
#    PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND                                              
# 1747297 root      20   0  108084    668    592 R 100.0  0.0   0:17.86 cat 
# bash cap_perf.sh `pidof cat`
# while cap pid 1747297
# [ perf record: Woken up 6 times to write data ]
# [ perf record: Captured and wrote 1.343 MB 1747297_16_10_36.data (9968 samples) ]
# # perf  report -i 1747297_16_10_36.data

target_pid=$1

cpu_threshold=50

start_perf() {

  perf record  -g -p $target_pid -o ${target_pid}_$(date +%H_%M_%S).data -- sleep 10 
}

while true; do

  cpu_percent=$(ps -p $target_pid -o %cpu | tail -n 1)
  
  if (( $(echo "$cpu_percent > $cpu_threshold" | bc -l) )); then
    echo "while cap pid $target_pid"

    start_perf $target_pid

    break
  fi


  sleep 5
done
