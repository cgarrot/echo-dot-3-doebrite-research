#!/bin/bash
for i in $(seq 1 30); do
  TS=$(date +%H:%M:%S)
  for n in $(seq 1 254); do (ping -c1 -W1 192.168.1.$n >/dev/null 2>&1 &); done
  sleep 3
  H=$(arp -an 2>/dev/null | grep -iE "DC:91:BF:XX:XX:XX|D6:91:BF:XX:XX:XX|4c:2c:f7" | head -2)
  if [ -n "$H" ]; then echo "[$TS] ★ ECHO SUR LE LAN:"; echo "$H"; exit 0; fi
  echo "[$TS] echo absent (tour $i)"
  sleep 12
done
