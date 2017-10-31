// IPv4
// Tunnel
// Encryption Algorithm . AES-CBC 128
// Integrity Algorithm - SHA2_256_128
//TODO all keys, vectors and routing are static
package main

import "github.com/intel-go/yanff/common"
import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "unsafe"
import "math"
import "bytes"

import "crypto/aes"
import "crypto/cipher"
import "crypto/hmac"
import "crypto/sha256"
import "hash"
import "flag"

func main() {
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	flag.Parse()

	config := flow.Config{DisableScheduler: *noscheduler}
	flow.SystemInit(&config)

	input := flow.SetReceiver(0)
	flow.SetHandler(input, outbound, *(new(context)))
	flow.SetHandler(input, inbound, *(new(context)))
	flow.SetSender(input, 1)

	flow.SystemStart()
}

type context struct {
	hmac_111      hash.Hash
	encrypter_111 cipher.BlockMode
	decrypter_111 cipher.BlockMode
}

type setIVer interface {
	SetIV([]byte)
}

func (c context) Copy() interface{} {
	n := new(context)
	//TODO Shouldn't be static
	secretKey := "123456789 123456789 123456789 12"
	n.hmac_111 = hmac.New(sha256.New, []byte(secretKey))
	//TODO Shouldn't be static
	key := "AES128Key-16Char"
	block_111, _ := aes.NewCipher([]byte(key))
	n.encrypter_111 = cipher.NewCBCEncrypter(block_111, make([]byte, 16))
	n.decrypter_111 = cipher.NewCBCDecrypter(block_111, make([]byte, 16))
	return n
}

func (c context) Delete() {
}

const esp = 0x32
const SPI_111 = 111
const espHeadLen = 24
const authLen = 16
const espTailLen = authLen + 2
const etherLen = common.EtherLen
const outerIPLen = common.IPv4MinLen

type espHeader struct {
	SPI uint32
	SEQ uint32
	IV  [16]byte
}

type espTail struct {
	paddingLen uint8
	nextIP     uint8
	Auth       [authLen]byte
}

// General inbound processing
func inbound(currentPacket *packet.Packet, context flow.UserContext) bool {
	length := currentPacket.GetPacketLen()
	currentESPHeader := (*espHeader)(unsafe.Pointer(currentPacket.Start() + etherLen + outerIPLen))
	currentESPTail := (*espTail)(unsafe.Pointer(currentPacket.Start() + uintptr(length) - espTailLen))
	// Security Association
	switch packet.SwapBytesUint32(currentESPHeader.SPI) {
	case SPI_111:
		encryptionPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Start()))[etherLen+outerIPLen+espHeadLen : length-authLen]
		authPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Start()))[etherLen+outerIPLen : length-authLen]
		if inbound_111(authPart, currentESPTail.Auth, currentESPHeader.IV, encryptionPart, context) == false {
			return false
		}
	default:
		return false
	}
	// Decapsulation
	currentPacket.DecapsulateHead(etherLen, outerIPLen+espHeadLen)
	currentPacket.DecapsulateTail(length-espTailLen-uint(currentESPTail.paddingLen), uint(currentESPTail.paddingLen)+espTailLen)

	return true
}

// Specific 111 mode inbound processing
func inbound_111(currentAuth []byte, Auth [authLen]byte, iv [16]byte, ciphertext []byte, context0 flow.UserContext) bool {
	context := context0.(*context)

	// Authentication
	context.hmac_111.Reset()
	context.hmac_111.Write(currentAuth)
	if bytes.Equal(context.hmac_111.Sum(nil)[0:authLen], Auth[:]) == false {
		return false
	}

	// Decryption
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return false
	}
	context.decrypter_111.(setIVer).SetIV(iv[:])
	context.decrypter_111.CryptBlocks(ciphertext, ciphertext)
	return true
}

// General outbound processing
func outbound(currentPacket *packet.Packet, context flow.UserContext) bool {
	// Encapsulation
	currentPacket.EncapsulateHead(etherLen, outerIPLen+espHeadLen)
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		//TODO Shouldn't be static
		ipv4.SrcAddr = packet.BytesToIPv4(111, 22, 3, 0)
		ipv4.DstAddr = packet.BytesToIPv4(3, 22, 111, 0)
		ipv4.VersionIhl = 0x45
		ipv4.NextProtoID = esp

		//TODO All packets will be encapsulated as 111 mode
		outbound_111(currentPacket, context)
	}
	return true
}

// Specific 111 mode outbound processing
func outbound_111(currentPacket *packet.Packet, context0 flow.UserContext) {
	context := context0.(*context)
	length := currentPacket.GetPacketLen()
	paddingLength := uint8((16 - (length-(etherLen+outerIPLen+espHeadLen)+2)%16) % 16)
	newLength := length + uint(paddingLength) + espTailLen
	currentPacket.EncapsulateTail(length, uint(paddingLength)+espTailLen)

	currentESPHeader := (*espHeader)(unsafe.Pointer(currentPacket.Start() + etherLen + outerIPLen))
	currentESPHeader.SPI = packet.SwapBytesUint32(SPI_111)
	//TODO Shouldn't be static
	currentESPHeader.IV = [16]byte{0x90, 0x9d, 0x78, 0xa8, 0x72, 0x70, 0x68, 0x00, 0x8f, 0xdc, 0x55, 0x73, 0xa3, 0x75, 0xb5, 0xa7}

	currentESPTail := (*espTail)(unsafe.Pointer(currentPacket.Start() + uintptr(newLength) - espTailLen))
	currentESPTail.paddingLen = paddingLength
	currentESPTail.nextIP = common.IPNumber

	// Encryption
	EncryptionPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Start()))[etherLen+outerIPLen+espHeadLen : newLength-authLen]
	context.encrypter_111.(setIVer).SetIV(currentESPHeader.IV[:])
	context.encrypter_111.CryptBlocks(EncryptionPart, EncryptionPart)

	// Authentication
	context.hmac_111.Reset()
	AuthPart := (*[math.MaxInt32]byte)(unsafe.Pointer(currentPacket.Start()))[etherLen+outerIPLen : newLength-authLen]
	context.hmac_111.Write(AuthPart)
	copy(currentESPTail.Auth[:], context.hmac_111.Sum(nil))
}
