"""Classe representando um pacote tcp geral

Esta classe contem todos os metodos e campos necessarios para representar,
serialiar, e desserializar um pacote tcp
"""


__version__ = "0.2"


import struct
import os

FLAGS_FIN = 1 << 0
FLAGS_SYN = 1 << 1
FLAGS_RST = 1 << 2
FLAGS_ACK = 1 << 4

class Pacote:


  def __init__(
      self, ip_origem, porta_origem, ip_destino, porta_destino, 
      numero_de_sequencia, numero_de_acknowledgement, tamanho_de_janela, 
      ponteiro_de_urgencia, conteudo):
    self.ip_origem = ip_origem
    self.porta_origem = porta_origem
    self.porta_destino = porta_destino
    self.ip_destino = ip_destino
    self.numero_de_sequencia = numero_de_sequencia
    self.numero_de_acknowledgement = numero_de_acknowledgement
    self.tamanho_de_janela = tamanho_de_janela
    self.ponteiro_de_urgencia = ponteiro_de_urgencia
    self.conteudo = conteudo
    self.flags = 5 << 12


  def concerta_segmento(self, segmento, ip_origem, ip_destino):
    pseudo_cabecalho = str2endereco(ip_origem)  \
                       + str2endereco(ip_destino) \
                       + struct.pack('!HH', 0x0006, len(segmento))
    seg = bytearray(segmento)
    seg[16:18] = b'\x00\x00'
    seg[16:18] = struct.pack('!H', self.calcula_checksum(pseudo_cabecalho + seg))
    return bytes(seg)


  def calcula_checksum(self, segmento):
    if len(segmento) % 2 == 1:
      segmento += b'\x00'
    checksum = 0
    for i in range(0, len(segmento), 2):
      x, = struct.unpack('!H', segmento[i:i+2])
      checksum += x
      while checksum > 0xffff:
        checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


  def serialize(self):
    cabecalho = struct.pack('!HHIIHHHH', self.porta_origem, \
                            self.porta_destino, self.numero_de_sequencia, \
                            self.numero_de_acknowledgement, self.flags,\
                            1024, 0, 0)
    segmento = cabecalho + self.conteudo
    segmento = self.concerta_segmento(segmento, self.ip_origem, self.ip_destino)
    return segmento


  def define_flags(self, fin, syn, rst, ack):
    flags = 5 << 12
    flags |= FLAGS_FIN if fin else 0x0
    flags |= FLAGS_SYN if syn else 0x0
    flags |= FLAGS_RST if rst else 0x0
    flags |= FLAGS_ACK if ack else 0x0
    self.flags = flags

  
  def ativa_flags(self, fin = False, syn = False, rst = False, ack = False):
    flags = self.flags
    flags |= FLAGS_FIN if fin else 0x0
    flags |= FLAGS_SYN if syn else 0x0
    flags |= FLAGS_RST if rst else 0x0
    flags |= FLAGS_ACK if ack else 0x0
    self.flags = flags


  def desativa_flags(self, fin = False, syn = False, rst = False, ack = False):
    flags = self.flags
    flags &= 0xffff - FLAGS_FIN if fin else 0xffff
    flags &= 0xffff - FLAGS_SYN if syn else 0xffff
    flags &= 0xffff - FLAGS_RST if rst else 0xffff
    flags &= 0xffff - FLAGS_ACK if ack else 0xffff
    self.flags = flags

  def checa_flags(self):
    retorno = []
    retorno.append((self.flags & FLAGS_FIN) != 0x0)
    retorno.append((self.flags & FLAGS_SYN) != 0x0)
    retorno.append((self.flags & FLAGS_RST) != 0x0)
    retorno.append((self.flags & FLAGS_ACK) != 0x0)
    return retorno


def traduz_cabecalho_ipv4(bin):
  versao = bin[0] >> 4
  ihl = bin[0] & 0xf
  assert versao == 4
  ip_origem = endereco2str(bin[12:16])
  ip_destino = endereco2str(bin[16:20])
  segmento = bin[4*ihl:]
  return ip_origem, ip_destino, segmento


def endereco2str(endereco):
  return '%d.%d.%d.%d' % tuple(int(x) for x in endereco)


def str2endereco(endereco):
  return bytes(int(x) for x in endereco.split('.'))


def traduz_pacote(binario):
  ip_origem, \
  ip_destino, \
  cabecalho = traduz_cabecalho_ipv4(binario)
  porta_origem, \
  porta_destino, \
  numero_de_sequencia, \
  numero_de_acknowledgement, \
  flags, \
  tamanho_da_janela, \
  checksum, \
  ponteiro_de_urgencia = struct.unpack('!HHIIHHHH', cabecalho[:20])
  tcp_offset = flags >> 12
  #tcp_offset = int(tcp_offset,base=15)
  #if porta_destino == 7000: print('tcp_offset : ', tcp_offset)
  conteudo = binario[tcp_offset*8:]
  p = Pacote(ip_origem, porta_origem, ip_destino, porta_destino,
             numero_de_sequencia, numero_de_acknowledgement, tamanho_da_janela,
             ponteiro_de_urgencia, conteudo)
  p.define_flags(flags & FLAGS_FIN != 0x0,
                 flags & FLAGS_SYN != 0x0,
                 flags & FLAGS_RST != 0x0,
                 flags & FLAGS_ACK != 0x0)
  return p
                 
 
