#!/bin/bash
# which container cost a lot of time by “housekeeping” 
#  bash check-slow-container.sh >>check-slow-container.log 2>&1
# author muyuan.ymy
for my in {1..86400}
    do
    echo `date`
    TIMEFORMAT=%R 
    time docker ps --format "{{.ID}}\t{{.Names}}" | while read id name
         do 
         echo -e "\nCheck Container: $name : $id\n"
         echo -n "docker inspect exec const time: "
         time docker inspect $id 2>&1  > /dev/null
         done
    echo -e "docker ps took Total Time"
    sleep 15
    done
