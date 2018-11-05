import os
import pacote
import conexao

class Sock:
  

  def __init__(self, fd, porta):
    self.porta = porta
    self.conexoes = {}
    self.fd = fd


  def recebe_pacote(self, pack):
    #tenho de dar um jeito de arrumar isso
    if not (pack.ip_origem, pack.porta_origem) in self.conexoes.keys():
      self.conexoes[(pack.ip_origem, pack.porta_origem)] = conexao.Conexao(500,pack.ip_origem,pack.porta_origem, pack.ip_destino, pack.porta_destino)
    flags = pack.checa_flags() 
    print('INCOMING > ip origem : ',pack.ip_origem, \
          ' | porta origem : ', pack.porta_origem, \
          ' | ip destino : ', pack.ip_destino,\
          ' | porta destino : ',pack.porta_destino,\
          ' | numero de sequencia : ', pack.numero_de_sequencia, \
          ' | numero de ack :', pack.numero_de_acknowledgement,\
          ' | FIN : ', flags[0], ' | SYN : ', flags[1],\
          ' | RST : ', flags[2], ' | ACK : ', flags[3],
          ' | conteudo : ', pack.conteudo.decode("UTF-8") if len(pack.conteudo) > 0 else '""')
    p = self.conexoes[(pack.ip_origem, pack.porta_origem)].recebe_pacote(pack)
    for packet in p:
      flags = packet.checa_flags()
      if type(packet.conteudo) is int:
        packet.conteudo = packet.conteudo.to_bytes(2, byteorder='big')
      print('OUTGOING > ip origem : ',packet.ip_origem, \
            ' | porta origem : ', packet.porta_origem, \
            ' | ip destino : ', packet.ip_destino,\
            ' | porta destino : ',packet.porta_destino,\
            ' | numero de sequencia : ', packet.numero_de_sequencia, \
            ' | numero de ack :', packet.numero_de_acknowledgement,\
            ' | FIN : ', flags[0], ' | SYN : ', flags[1],\
            ' | RST : ', flags[2], ' | ACK : ', flags[3],
            ' | conteudo : NOPE')#, packet.conteudo.decode("UTF-8") if len(pack.conteudo) > 0 else '""')

      #if packet.numero_de_sequencia == 0:
      #  packet.numero_de_sequencia = self.conexoes[(pack.ip_origem, pack.porta_origem)].
      pack.ativa_flags(fin = False, syn = False, rst = False, ack = True)
      self.fd.sendto(packet.serialize(), (packet.ip_destino, \
                                          packet.porta_destino))



    
