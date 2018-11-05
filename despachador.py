#!/usr/bin/python3

import struct
import pacote
import sock
import asyncio
import socket

class Despachador:


  def __init__(self):
    self.meias = {}
    self.fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    self.loop = asyncio.get_event_loop()
    self.loop.add_reader(self.fd, self.recebe_pacote, self.fd)

  def recebe_pacote(self,fd):
    binario = fd.recv(12000)
    pac = pacote.traduz_pacote(binario)
    if not pac.porta_destino in self.meias.keys():
      return
    self.meias[pac.porta_destino].recebe_pacote(pac)


  def registra_servico(self, porta):
    self.meias[porta] = sock.Sock(self.fd,porta)
