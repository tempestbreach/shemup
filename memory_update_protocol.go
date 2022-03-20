package shemup

import(
    "fmt"
    "crypto/aes"
    "crypto/cipher"
    "encoding/binary"
    "encoding/hex"

    "github.com/chmike/cmac-go"
)

type MemoryUpdateInfo struct {
    KEY_NEW         []byte
    KEY_AuthID      []byte
    UID             []byte
    ID              int
    AuthID          int
    C_ID            int
    F_ID            int
}

type MemoryUpdateMessage struct {
    M1              []byte      `json:"m1"`
    M2              []byte      `json:"m2"`
    M3              []byte      `json:"m3"`
    M4              []byte      `json:"m4"`
    M5              []byte      `json:"m5"`
}

func encryptECB(k, v []byte) ([]byte, error){
    if !validKey(k) {
        return nil, fmt.Errorf("length of the key is invalid: %d\n", len(k))
    }

    block, err := aes.NewCipher(k)
    if err != nil {
        return nil, err
    }

    if len(v)%block.BlockSize() != 0 {
        return nil, fmt.Errorf("source data must be an integer multiple of %d; current length: %d\n", block.BlockSize(), len(v))
    }

    var dst []byte
    tmpData := make([]byte, block.BlockSize())
    for i := 0; i < len(v); i += block.BlockSize() {
        block.Encrypt(tmpData, v[i:i+block.BlockSize()])
        dst = append(dst, tmpData...)
    }

    return dst, nil
}

func encryptCBC(k, v, iv []byte) ([]byte, error) {
    if len(v)%aes.BlockSize != 0 {
        return nil, fmt.Errorf("source data must be an integer multiple of %d; current length: %d\n", aes.BlockSize, len(v))
    }

    block, err := aes.NewCipher(k)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(v))

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext, v)


    return ciphertext, err
}

func generateCMAC(k, m []byte) ([]byte, error) {
    cm, err := cmac.New(aes.NewCipher, k)
    if err != nil {
        return nil, err
    }

    cm.Write(m)

    mac := cm.Sum(nil)
    return mac, err
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		fmt.Printf("length of byte slices is not equivalent: %d != %d\n", len(a), len(b))
	}

	buf := make([]byte, len(a))

	for i := range a {
		buf[i] = a[i] ^ b[i]
	}

	return buf
}

func mpCompress(data []byte) []byte {
    l := len(data)
    CHUNK_LEN := 16      // 128bit (16byte) chunks
    out := make([]byte, CHUNK_LEN)

    for i := 0; i < l; i += CHUNK_LEN {
		chunk := data[i : i+CHUNK_LEN]
		enc, err := encryptECB(out, chunk)
        if err != nil {
            fmt.Println(err)
        }
		out = xorBytes(xorBytes(enc, chunk), out)
	}

    return out
}

func mpKDF(k, c []byte) []byte {
    data := append(k, c...)
    return mpCompress(data)
}

func generateMessage(info MemoryUpdateInfo, KEY_UPDATE_ENC_C []byte, KEY_UPDATE_MAC_C []byte) MemoryUpdateMessage {

    k1 := mpKDF(info.KEY_AuthID, KEY_UPDATE_ENC_C)
	k2 := mpKDF(info.KEY_AuthID, KEY_UPDATE_MAC_C)
	k3 := mpKDF(info.KEY_NEW, KEY_UPDATE_ENC_C)
	k4 := mpKDF(info.KEY_NEW, KEY_UPDATE_MAC_C)

    o1 := []byte{uint8( (info.ID << 4) | (info.AuthID & 0x0F) )}
    m1 := append(info.UID, o1...)

    o2 := toBytes((info.C_ID << 4) | (0x0F & (info.F_ID >> 2)), 4)
    o3 := []byte{(uint8((info.F_ID << 6) & 0x03))}
    o4 := make([]byte, 11)
    f1 := append(o2, o3...)
    f1 = append(f1, o4...)
    f1 = append(f1, info.KEY_NEW...)
    f2 := make([]byte, 16)
	m2, err := encryptCBC(k1, f1, f2)
    if err != nil {
        fmt.Println(err)
    }

    f3 := append(m1, m2...)
	m3, err := generateCMAC(k2, f3)
    if err != nil {
        fmt.Println(err)
    }

    o5 := toBytes(((info.C_ID << 4) | 0x08), 4)
    o6 := make([]byte, 12)
    f4 := append(o5, o6...)
    o7, err := encryptECB(k3, f4)
    if err != nil {
        fmt.Println(err)
    }
	m4 := append(m1, o7...)

	m5, err := generateCMAC(k4, m4)
    if err != nil {
        fmt.Println(err)
    }

    mum := MemoryUpdateMessage{
        M1: m1,
        M2: m2,
        M3: m3,
        M4: m4,
        M5: m5,
    }

    return mum
}



func GenerateMessageBasic(info MemoryUpdateInfo) MemoryUpdateMessage {
    d1, err := hex.DecodeString("010153484500800000000000000000B0")
    d2, err := hex.DecodeString("010253484500800000000000000000B0")
    if err != nil {
        fmt.Println(err)
    }

    mum := generateMessage(info, d1, d2)
    return mum
}

func toBytes(d int, size uint64) []byte {
    bs := make([]byte, 2)
    binary.BigEndian.PutUint16(bs, uint16(d))

    bs2 := make([]byte, size - 2)
    bs2 = append(bs2, bs...)

    return bs2
}

func validKey(key []byte) bool {
    k := len(key)
    switch k {
    default:
        return false
    case 16, 24, 32:
        return true
    }
}
