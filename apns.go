package apns

import (
    "bytes"
    "crypto/tls"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "sync"
)

const (
    APNS_HOST_DEVELOPMENT   = "gateway.sandbox.push.apple.com:2195"
    APNS_HOST_PRODUCTION    = "gateway.push.apple.com:2195"
)

type Conn struct {
    connection  *tls.Conn
    config      tls.Config
    connected   bool
    mu          sync.Mutex
}

func Client(certFile, keyFile string) (conn *Conn, err error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }

    conf := tls.Config{Certificates : []tls.Certificate{cert}}

    conn = &Conn {
        connection : nil,
        config : conf,
        connected : false,
    }

    conn.connect()

    return conn, nil
}

func (this *Conn) connect() (err error) {
    if this.connected {
        return nil
    }

    if this.connection != nil {
        this.Close()
    }

    conn, err := tls.Dial("tcp", APNS_HOST_DEVELOPMENT, &this.config)
    if err != nil {
        return err
    }

    this.connection = conn
    this.connected = true

    return nil
}

func (this *Conn) Close() {
    if !this.connected || this.connection == nil {
        return
    }

    this.connection.Close()
    this.connected = false
}

func (this *Conn) SendPayload(deviceToken string, payload map[string]interface{}) error {

    hpl, err := json.Marshal(payload)
    if err != nil {
        return err
    }

    hdt, err := hex.DecodeString(deviceToken)
    if err != nil {
        return err
    }

    buffer := bytes.NewBuffer([]byte{})
    writeBytesBigEndian(buffer, uint8(1))
    writeBytesBigEndian(buffer, uint32(1))
    writeBytesBigEndian(buffer, uint32(60 * 60))
    writeBytesBigEndian(buffer, uint16(len(hdt)))
    writeBytesBigEndian(buffer, hdt)
    writeBytesBigEndian(buffer, uint16(len(hpl)))
    writeBytesBigEndian(buffer, hpl)

    noti := buffer.Bytes()

    this.mu.Lock()
    defer this.mu.Unlock()

    _, err = this.connection.Write(noti)
    if err != nil {
        return err
    }

    return nil
}

func writeBytesBigEndian(buffer *bytes.Buffer, v interface{}) {
    binary.Write(buffer, binary.BigEndian, v)
}
