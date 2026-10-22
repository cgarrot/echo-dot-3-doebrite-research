#!/bin/bash
# surveillance legere : cherche la MAC de l Echo dc:91:bf:bb:72:4a sur le /24
for i in $(seq 1 40); do
  TS=$(date +%H:%M:%S)
  # ping doux de la plage (1 par IP, 1s)
  for n in $(seq 1 254); do (ping -c1 -W1 192.168.1.$n >/dev/null 2>&1 &) ; done
  sleep 3
  HIT=$(arp -an 2>/dev/null | grep -i "dc:91:bf:bb:72:4a" | head -1)
  if [ -n "$HIT" ]; then
    IP=$(echo "$HIT" | sed -E 's/.*\(([0-9.]+)\).*/\1/')
    echo "[$TS] ★ ECHO REVENU sur $IP  (MAC $HIT)"
    for p in 5541 4070 1080 8888; do
      (echo >/dev/tcp/$IP/$p) >/dev/null 2>&1 && echo "      port $p OUVERT" || echo "      port $p ferme"
    done
    exit 0
  fi
  echo "[$TS] echo absent (tour $i/40)"
  sleep 15
done
echo "ECHO TOUJOURS ABSENT apres ~12 min"
