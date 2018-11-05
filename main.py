#!/usr/bin/python3
#iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#

import despachador

if __name__ == "__main__":
  cleyton = despachador.Despachador()
  cleyton.registra_servico(7000)
  cleyton.loop.run_forever()
