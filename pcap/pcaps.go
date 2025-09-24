package pcap

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/MKSx/tlsd/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Fragment struct {
	Data      []byte
	Timestamp time.Time
}

type FragmentInfo struct {
	Length uint16
	Count  int
}

type Stream struct {
	ID              string
	Version         uint16
	ClientRandom    []byte
	ServerRandom    []byte
	PreMasterSecret []byte
	CipherSuite     uint16
	Done            bool
	TLS             *tlsx.TLSStream
	Fragments       map[uint16][]Fragment
	FragmentsLength map[uint16]*FragmentInfo
	NextSeq         uint32
}

type PCAPHandler struct {
	handler    *pcap.Handle
	key        *rsa.PrivateKey
	serverPort layers.TCPPort
	stream     map[string]*Stream
}

type packetContext struct {
	ID        string
	Timestamp time.Time
}

type TCPConnection struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type TCPReassembler struct {
	connections map[TCPConnection][]byte
}

func NewPCAPHandler(filename string, server_key string, server_port int) (*PCAPHandler, error) {
	var err error

	ret := &PCAPHandler{
		serverPort: layers.TCPPort(server_port),
	}

	ret.handler, err = pcap.OpenOffline(filename)

	if err != nil {
		return nil, err
	}

	ret.key, err = tlsx.LoadPrivateKey(server_key)

	if err != nil {
		return nil, err
	}

	ret.stream = map[string]*Stream{}

	return ret, nil

}

func (p *PCAPHandler) Proccess(callback func(string, string, bool, time.Time)) {

	packetSource := gopacket.NewPacketSource(p.handler, p.handler.LinkType())

	//fragment_list :=

	for packet := range packetSource.Packets() {

		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		if len(tcp.Payload) < 1 {
			continue
		}

		cId := p.getConnectionID(packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcp.DstPort)
		/*if cId != "172.21.71.142:52018-10.238.61.95:443" {
			continue
		}*/

		stream, ok := p.stream[cId]

		if !ok || !stream.Done {
			//fmt.Println("!ok !stream.Done")
			//fmt.Println(packet)
			p.processTLS(tcp.Payload, cId, tcp.DstPort == p.serverPort, packet.Metadata().Timestamp, callback)
		} else {

			if tcp.ACK {
				if stream.Done {

					_, ok := stream.Fragments[tcp.Window]

					if !ok {
						version, length, payload_length := GetApplicationDataInfo(tcp.Payload)

						if version != stream.Version || length < 1 {
							continue
						}

						if length == payload_length {
							p.processTLS(tcp.Payload, cId, tcp.DstPort == p.serverPort, packet.Metadata().Timestamp, callback)
							continue
						}

						stream.Fragments[tcp.Window] = []Fragment{
							{
								Data:      tcp.Payload,
								Timestamp: packet.Metadata().Timestamp,
							},
						}
						stream.FragmentsLength[tcp.Window] = &FragmentInfo{
							Length: length,
							Count:  int(payload_length),
						}

						//fmt.Printf("Version: %x\nLength: %d\nPaylaod Len: %d\n", version, length, len(tcp.Payload))
						continue
					}

					//log.Printf("Adicionando novo fragmento, window: %d", tcp.Window)
					stream.Fragments[tcp.Window] = append(stream.Fragments[tcp.Window], Fragment{
						Data:      tcp.Payload,
						Timestamp: packet.Metadata().Timestamp,
					})

					stream.FragmentsLength[tcp.Window].Count += len(tcp.Payload)

					if stream.FragmentsLength[tcp.Window].Count == int(stream.FragmentsLength[tcp.Window].Length) {
						//log.Printf("Último fragmento coletado, window: %d | %d", tcp.Window, len(stream.Fragments[tcp.Window]))

						buffer := bytes.Buffer{}

						for i := range stream.Fragments[tcp.Window] {
							//fmt.Printf("[%d] %s\n", tcp.Window, stream.Fragments[tcp.Window][i].Timestamp)
							buffer.Write(stream.Fragments[tcp.Window][i].Data)
						}

						delete(stream.Fragments, tcp.Window)
						delete(stream.FragmentsLength, tcp.Window)

						//log.Printf("Chamando process, window: %d", tcp.Window)
						p.processTLS(buffer.Bytes(), cId, tcp.DstPort == p.serverPort, packet.Metadata().Timestamp, callback)
					}
				}
			}

		}

	}

}

func (p *PCAPHandler) getConnectionID(src_ip string, src_port layers.TCPPort, dst_ip string, dst_port layers.TCPPort) string {
	if dst_port == p.serverPort {
		return fmt.Sprintf("%s:%d-%s:%d", src_ip, src_port, dst_ip, dst_port)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dst_ip, dst_port, src_ip, src_port)
}

func (p *PCAPHandler) Close() {
	p.handler.Close()
}
func (p *PCAPHandler) processTLS(payload []byte, id string, fromClient bool, tm time.Time, callback func(string, string, bool, time.Time)) {
	tlsMessageType := payload[0]

	stream, ok := p.stream[id]

	if !(tlsMessageType == TLS_HANDSHAKE || tlsMessageType == TLS_CHANGE_CIPHER_SPEC || tlsMessageType == TLS_APPLICATION_DATA || tlsMessageType == TLS_HANDSHAKE_ALERT) {
		return
	}

	if len(payload) < 50 {
		return
	}

	version := uint16(payload[1])<<8 | uint16(payload[2])

	if version < tlsx.VersionTLS10 || version > tlsx.VersionTLS13 {
		//log.Printf("Versão do TLS desconhecida: %x", version)
		//log.Printf("ID: %s | %s | %v", id, tm, fromClient)
		//log.Println(payload)

		return
	}

	if !ok && tlsMessageType != TLS_APPLICATION_DATA {
		p.stream[id] = &Stream{
			ID:              id,
			Version:         version,
			Fragments:       map[uint16][]Fragment{},
			FragmentsLength: map[uint16]*FragmentInfo{},
		}
		stream = p.stream[id]
		ok = true
	}

	if !ok {
		return
	}

	switch tlsMessageType {
	case TLS_HANDSHAKE:
		if stream.processHandshakeMessage(payload) {

			var err error

			stream.PreMasterSecret, err = rsa.DecryptPKCS1v15(nil, p.key, stream.PreMasterSecret)

			if err != nil {
				log.Printf("Falha ao descriptografar a chave pre master: %s", id)
				log.Println(err)

				delete(p.stream, id)
				return
			}

			stream.Done = true
			stream.TLS = tlsx.NewTLSStream()

			stream.TLS.CipherSuite = stream.CipherSuite
			stream.TLS.ClientRandom = stream.ClientRandom
			stream.TLS.ServerRandom = stream.ServerRandom
			stream.TLS.Version = stream.Version

			suite := tlsx.CipherSuiteByID(stream.CipherSuite)

			if suite == nil {
				log.Printf("Cipher Suite não encontrada: %x", stream.CipherSuite)

				delete(p.stream, id)
				return

			}

			stream.TLS.MasterKey = tlsx.MasterFromPreMasterSecret(stream.Version, tlsx.CipherSuiteByID(stream.CipherSuite), stream.PreMasterSecret, stream.ClientRandom, stream.ServerRandom)

			err = stream.TLS.EstablishConn()

			if err != nil {
				log.Printf("Falha ao estabelecer as chaves de comunicação para descriptografia: %s", id)
				log.Println(err)

				delete(p.stream, id)
				return
			}

			//fmt.Println("Comunicação estabelecida:", id)

		}
	case TLS_HANDSHAKE_ALERT:
		//fmt.Println("TLS_HANDSHAKE_ALERT")
		//fmt.Println(payload)
		if payload[5] == TLS_ALERT_TYPE_FATAL || (payload[5] == TLS_ALERT_TYPE_WARNING && payload[6] != TLS_ALERT_LEVEL_NO_RENEGOTIATION) {
			//fechou conexão
		}
		log.Printf("Conexão %s fechada\n", id)
		delete(p.stream, id)
		return
	case TLS_APPLICATION_DATA:
		if !stream.Done {
			//log.Println("A conexão não finalizou o Handshake")
			return
		}

		//log.Println("TLS_APPLICATION_DATA")

		//log.Println(hex.EncodeToString(payload))

		plain, err := stream.TLS.TLSDecrypt(payload, fromClient)
		if err != nil {
			//log.Printf("Falha ao tentar descriptografar a mensagem de: %s | %s", id, tm)
			return
		}

		callback(id, plain, fromClient, tm)
		//fmt.Println(plain)

	}

}

func (s *Stream) processHandshakeMessage(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	handshakeType := payload[5]

	payload = payload[6:]

	switch handshakeType {
	case TLS_HANDSHAKE_CLIENT_HELLO:
		s.ClientRandom = payload[5:37]
	case TLS_HANDSHAKE_SERVER_HELLO:

		s.Version = uint16(payload[3])<<8 | uint16(payload[4])

		s.ServerRandom = payload[5:37]

		index := payload[37]

		if int(index)+39 >= len(payload) {
			return false
		}

		s.CipherSuite = uint16(payload[payload[37]+38])<<8 | uint16(payload[payload[37]+39])

	case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:

		preMasterLen := int(payload[3])<<8 | int(payload[4])

		if preMasterLen+5 >= len(payload) {
			return false
		}

		s.PreMasterSecret = payload[5 : preMasterLen+5]

		return true

	}
	return false

}

func GetApplicationDataInfo(data []byte) (uint16, uint16, uint16) {
	if data[0] == 0x17 {
		version := uint16(data[1])<<8 | uint16(data[2])

		length := uint16(data[3])<<8 | uint16(data[4])

		return version, length, uint16(len(data[5:]))
	}

	return 0, 0, 0
}

func IsTLSApplicationData(data []byte) bool {
	if data[0] == 0x17 {
		version := uint16(data[1])<<8 | uint16(data[2])

		return version >= tlsx.VersionTLS10 && version <= tlsx.VersionTLS13

	}

	return false
}
