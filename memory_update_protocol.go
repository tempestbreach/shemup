package shemup

import(
    "fmt"
    // "bytes"
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

// func(m *MemoryUpdateMessage) ToMap()

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

// func encryptCBC(k, v, iv []byte) ([]byte, error) {
func encryptCBC(k, v, iv []byte) ([]byte, error) {
    if len(v)%aes.BlockSize != 0 {
        return nil, fmt.Errorf("source data must be an integer multiple of %d; current length: %d\n", aes.BlockSize, len(v))
    }

    block, err := aes.NewCipher(k)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize + len(v))
    // iv := ciphertext[:aes.BlockSize]
    // if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    //     return nil, err
    // }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], v)

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
    out := []byte("0000000000000000")

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

    fmt.Println(info.AuthID)
    fmt.Println(info.ID)

    b1 := info.UID
    fmt.Printf("info.UID = %T\n", b1)
    fmt.Println(b1)
    b2 := info.ID << 4
    fmt.Printf("b2: %T\n", b2)
    fmt.Println(b2)
    b3 := info.AuthID & 0x0F
    fmt.Printf("b3 = %T\n", b3)
    fmt.Println(b3)
    b4 := b2 | b3
    fmt.Printf("b4 = %T\n", b4)
    fmt.Println(b4)
    b5 := toBytes(uint(b4), 1)
    fmt.Printf("b5 = %T\n", b5)
    fmt.Println(b5)
    b6 := append(b1, b5...)
    fmt.Printf("b6 = %T\n", b6)
    fmt.Println(b6)
	m1 := b6

    fmt.Println("C_ID: ", info.C_ID, "\n")
    fmt.Println("F_ID: ", info.F_ID, "\n")
    c1 := (info.C_ID<<4 | 0x0F & (info.F_ID>>2))
    fmt.Println("c1: ", c1, "\n")
    c2 := uint(c1)
    fmt.Println("c2: ", c2, "\n")
    c3 := toBytes(c2, 4)
    fmt.Println("c3: ", c3, "\n")
    // c1 := toBytes(uint((info.C_ID<<4 | 0x0F & (info.F_ID>>2))), 4)
    c4 := toBytes(uint((info.F_ID<<6 & 0x03)), 1)
    c5 := []byte("00000000000")
    c6 := info.KEY_NEW
    f1 := append(c3, c4...)
    f1 = append(f1, c5...)
    f1 = append(f1, c6...)
	m2, err := encryptCBC(k1, f1, []byte("0000000000000000"))
    if err != nil {
        fmt.Println(err)
    }

    d1 := append(m1, m2...)
	m3, err := generateCMAC(k2, d1)
    if err != nil {
        fmt.Println(err)
    }

    e1 := toBytes(uint(info.C_ID << 4 | 0x08), 4)
    e2 := append(e1, []byte("000000000000")...)
    e3, err := encryptECB(k3, e2)
    if err != nil {
        fmt.Println(err)
    }
	m4 := append(m1, e3...)

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

// func generateMessage(info MemoryUpdateInfo, KEY_UPDATE_ENC_C []byte, KEY_UPDATE_MAC_C []byte) MemoryUpdateMessage {
// 	k1 := mpKDF(info.KEY_AuthID, KEY_UPDATE_ENC_C)
// 	k2 := mpKDF(info.KEY_AuthID, KEY_UPDATE_MAC_C)
// 	k3 := mpKDF(info.KEY_NEW, KEY_UPDATE_ENC_C)
// 	k4 := mpKDF(info.KEY_NEW, KEY_UPDATE_MAC_C)
//
//     fmt.Println(info.AuthID)
//     fmt.Println(info.ID)
//
//     b1 := info.UID
//     fmt.Printf("\ninfo.UID = %T", b1)
//     fmt.Println(b1)
//     b2 := ((info.ID << 4) | (info.AuthID & 0x0F))
//     fmt.Printf("\nb2: %T", b2)
//     fmt.Println(b2)
//     b3 := toBytes(uint(b2), 1)
//     fmt.Printf("\nb3 = %T", b3)
//     fmt.Println(b3)
//     b4 := append(b1, b3...)
//     fmt.Printf("\nm1 = %T", b4)
// 	m1 := b4
//
//     c1 := toBytes(uint((info.C_ID<<4 | 0x0F & (info.F_ID>>2))), 4)
//     c2 := toBytes(uint((info.F_ID<<6 & 0x03)), 1)
//     c3 := []byte("00000000000")
//     c4 := info.KEY_NEW
//     f1 := append(c1, c2...)
//     f1 = append(f1, c3...)
//     f1 = append(f1, c4...)
// 	m2, err := encryptCBC(k1, f1, []byte("0000000000000000"))
//     if err != nil {
//         fmt.Println(err)
//     }
//
//     d1 := append(m1, m2...)
// 	m3, err := generateCMAC(k2, d1)
//     if err != nil {
//         fmt.Println(err)
//     }
//
//     e1 := toBytes(uint(info.C_ID << 4 | 0x08), 4)
//     e2 := append(e1, []byte("000000000000")...)
//     e3, err := encryptECB(k3, e2)
//     if err != nil {
//         fmt.Println(err)
//     }
// 	m4 := append(m1, e3...)
//
// 	m5, err := generateCMAC(k4, m4)
//     if err != nil {
//         fmt.Println(err)
//     }
//
//     mum := MemoryUpdateMessage{
//         M1: m1,
//         M2: m2,
//         M3: m3,
//         M4: m4,
//         M5: m5,
//     }
// 	return mum
// }

func GenerateMessageBasic(info MemoryUpdateInfo) MemoryUpdateMessage {
    d1, err := hex.DecodeString("010153484500800000000000000000B0")
    d2, err := hex.DecodeString("010253484500800000000000000000B0")
    if err != nil {
        fmt.Println(err)
    }

    mum := generateMessage(info, d1, d2)
    return mum
}

// func generate_message(info MemoryUpdateInfo, KEY_UPDATE_ENC_C []byte, KEY_UPDATE_MAC_C []byte) MemoryUpdateMessage {
// 	k1 := mp_kdf(info.KEY_AuthID, KEY_UPDATE_ENC_C)
// 	k2 := mp_kdf(info.KEY_AuthID, KEY_UPDATE_MAC_C)
// 	k3 := mp_kdf(info.KEY_NEW, KEY_UPDATE_ENC_C)
// 	k4 := mp_kdf(info.KEY_NEW, KEY_UPDATE_MAC_C)
// 	m1 := info.UID + (info.ID<<4|info.AuthID&15).to_bytes(1, "big")
// 	m2 := encrypt_cbc(k1, (info.C_ID<<4|15&(info.F_ID>>2)).to_bytes(4, "big")+(info.F_ID<<6&3).to_bytes(1, "big")+bytes(func(repeated []int, n int) (result []int) {
// 		for i := 0; i < n; i++ {
// 			result = append(result, repeated...)
// 		}
// 		return result
// 	}([]int{0}, 11))+info.KEY_NEW, bytes([]int{0}*16))
// 	m3 := generate_cmac(k2, m1+m2)
// 	m4 := m1 + encrypt_ecb(k3, (info.C_ID<<4|8).to_bytes(4, "big")+bytes(func(repeated []int, n int) (result []int) {
// 		for i := 0; i < n; i++ {
// 			result = append(result, repeated...)
// 		}
// 		return result
// 	}([]int{0}, 12)))
// 	m5 := generate_cmac(k4, m4)
// 	return MemoryUpdateMessage(m1, m2, m3, m4, m5)
// }

func toBytes(d uint, size uint64) []byte {
    // fmt.Printf("Converting to bytes: %d with size %d\n", d, size)
    // n := uint64(d)
    // bs := make([]byte, size)
    // binary.BigEndian.PutUint64(bs, n)
    //
    // return bs
    // buf := make([]byte, binary.MaxVarintLen64)
	// n := binary.PutUvarint(buf, uint64(z))
    buf := make([]byte, size)
	n := binary.PutUvarint(buf, uint64(d))
    return buf[:n]
}

// func XORBytes(a, b []byte) ([]byte, error) {
// 	if len(a) != len(b) {
// 		return nil, fmt.Errorf("length of byte slices is not equivalent: %d != %d", len(a), len(b))
// 	}
//
// 	buf := make([]byte, len(a))
//
// 	for i := range a {
// 		buf[i] = a[i] ^ b[i]
// 	}
//
// 	return buf, nil
// }

func validKey(key []byte) bool {
    k := len(key)
    switch k {
    default:
        return false
    case 16, 24, 32:
        return true
    }
}
