""" Classe Conexao

Essa classe representa uma conxeao tcp
Essa classe tambem eh responsavel pelos timers
"""


import pacote
import os
import time 
import hashlib
import struct
import pacote

class Conexao:

  def __init__(self, segredo, ip_origem, porta_origem, ip_destino, porta_destino):
    self.segredo = segredo
    self.buffer_de_entrada = b""
    self.buffer_de_saida = b""
    self.nao_confirmados = b""
    self.numero_de_acknowledgement = 0
    self.numero_de_segmento = 0
    self.buffer_disponivel_do_cliente = 10
    self.tamanho_da_janela = 10
    self.fucao_de_aplicacao = temporario
    self.tamanho_max_de_segmento = 1024
    self.ip_origem = ip_origem
    self.porta_origem = porta_origem
    self.ip_destino = ip_destino
    self.porta_destino = porta_destino

    
  def recebe_pacote(self, pac):

    self.buffer_de_entrada += pac.conteudo
    going_to_ack = True if len(pac.conteudo) else False
    if len(self.buffer_de_entrada) > 0:
      digerido, inicio, fim = self.fucao_de_aplicacao(self.buffer_de_entrada)
      self.buffer_de_saida += digerido
      self.buffer_de_entrada = self.buffer_de_entrada[inicio:fim]
    flags = pac.checa_flags()

    retorno = []
    #se for fin, danesse o resto
    if flags[0]:
      retorno.append(self.on_fin(pac))
    elif flags[1]: 
      retorno.append(self.on_syn(pac))
    elif flags[2]:
      pass
      #retorno.append(self.on_rst(pac))
    elif flags[3]:
      retorno.append(self.on_ack(pac))
    retorno.append(self.processa_buffer_de_saida())

    retorno = planifica(retorno)
    if len(pac.conteudo) > 0 and len(retorno) == 0:
      retorno.append(pacote.Pacote(self.ip_destino,self.porta_destino,self.ip_origem,self.porta_origem,0,0,self.tamanho_da_janela,0,b''))
      
    ack = pac.numero_de_sequencia+len(pac.conteudo)
    seg = pac.numero_de_acknowledgement
    
    for p in retorno:
      if p.checa_flags()[0]:
        p.numero_de_sequencia = seg + 1
      elif not p.checa_flags()[1]:
        p.numero_de_acknowledgement = ack
        p.numero_de_sequencia = seg
      p.ativa_flags(ack=True)
    return retorno


  def on_fin(self, pack):
   fin = gera_pacote_de_resposta(pack)
   fin.ativa_flags(fin=True)
   return fin


  def on_syn(self, pack):
    tcp_cookie = gen_tcp_cookie(pack.ip_destino, pack.porta_destino,
                                pack.ip_origem, pack.porta_origem, \
                                self.segredo)
    synack = pacote.Pacote(pack.ip_destino, pack.porta_destino, pack.ip_origem,
                           pack.porta_origem, tcp_cookie, 
                           pack.numero_de_sequencia+1,0,0,b'')
    synack.define_flags(fin = False, syn = True, rst = False, ack = True)
    self.numero_de_acknowledgement = tcp_cookie
    self.numero_de_segmento = pack.numero_de_sequencia + 1
    return synack


  def on_ack(self, pack):
    self.buffer_disponivel_do_cliente = pack.tamanho_de_janela
    #if self.buffer_disponivel_do_client > 0: timer

    diff = pack.numero_de_acknowledgement - self.numero_de_acknowledgement - len(self.nao_confirmados)

    if diff < 0:
      self.nao_confirmados = self.nao_confirmados[abs(diff):]
      self.tamanho_da_janela /= 2
    else:
      self.tamanho_da_janela *= 2
      self.nao_confirmados = b""
    
    self.numero_de_acknowledgement = pack.numero_de_acknowledgement
    return []

  '''considerando tamanho maximo de pacote e buffer do cliente e minha janela'''
  def processa_buffer_de_saida(self):
    prontos = []
    buf_size = min(len(self.buffer_de_saida),self.buffer_disponivel_do_cliente,self.tamanho_da_janela-len(self.nao_confirmados))
    temp_buff = self.buffer_de_saida[:buf_size]
    self.nao_confirmados += temp_buff
    for offset in range(0,buf_size,self.tamanho_max_de_segmento):
      print("buf_size", buf_size, "actual size", len(temp_buff))
      prontos.append(pacote.Pacote(self.ip_destino,self.porta_destino, self.ip_origem, self.porta_origem\
      ,0,0,self.tamanho_da_janela,0,temp_buff[offset*self.tamanho_max_de_segmento:(offset+1)*self.tamanho_max_de_segmento]))
      
    self.buffer_de_saida = self.buffer_de_saida[buf_size:]
    return prontos

  
def gen_tcp_cookie(ip_origem, porta_origem, ip_destino, porta_destino, segredo):
  epoch = ((int)(time.time()) << 10) & 0xffff
  tcp_cookie = struct.unpack('I',
                             hashlib.md5(
                               str(epoch).encode("UTF-8")
                               +  str(segredo).encode("UTF-8")
                               + str(ip_origem).encode("UTF-8")
                               + str(porta_origem).encode("UTF-8")
                               + str(ip_destino).encode("UTF-8")
                               + str(porta_destino).encode("UTF-8")
                             ) .digest()[-4:])
  return tcp_cookie[0]


def gera_pacote_de_resposta(pack):
  return pacote.Pacote(pack.ip_destino, pack.porta_destino, pack.ip_origem,
                       pack.porta_origem, pack.numero_de_acknowledgement, 
                       pack.numero_de_sequencia+len(pack.conteudo),1024,0,b'')


def temporario(buffer_de_entrada):
  return (buffer_de_entrada, 0, 0)

def planifica(lista):
  retorno = []
  for l in lista:
    if type(l) == list:
      l = planifica(l)
      for k in l:
        retorno.append(k)
    else:
      retorno.append(l)
  return retorno