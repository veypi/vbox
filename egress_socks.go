package vbox

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func (e *egressEndpoint) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := e.socksAuthenticate(conn); err != nil {
		return
	}
	address, err := readSOCKSRequest(conn)
	if err != nil {
		_ = writeSOCKSReply(conn, 0x01)
		return
	}
	if e.isSelfTarget(address) {
		_ = writeSOCKSReply(conn, 0x02)
		return
	}
	if !e.acquireTunnel() {
		_ = writeSOCKSReply(conn, 0x06)
		return
	}
	defer e.releaseTunnel()
	remote, err := e.dialer.dialContext(e.ctx, address)
	if err != nil {
		_ = writeSOCKSReply(conn, 0x02)
		return
	}
	if err := writeSOCKSReply(conn, 0x00); err != nil {
		_ = remote.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	e.tunnel(e.ctx, conn, remote)
}

func (e *egressEndpoint) socksAuthenticate(conn net.Conn) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 0x05 || greeting[1] == 0 {
		return fmt.Errorf("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	method := byte(0xff)
	for _, candidate := range methods {
		if candidate == 0x02 {
			method = 0x02
			break
		}
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return err
	}
	if method == 0xff {
		return fmt.Errorf("SOCKS authentication method unavailable")
	}
	var authHeader [2]byte
	if _, err := io.ReadFull(conn, authHeader[:]); err != nil {
		return err
	}
	if authHeader[0] != 0x01 {
		return fmt.Errorf("invalid SOCKS auth version")
	}
	username := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	userOK := subtle.ConstantTimeCompare(username, []byte("vbox"))
	passwordOK := subtle.ConstantTimeCompare(password, []byte(e.token))
	if userOK&passwordOK != 1 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("SOCKS authentication failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSOCKSRequest(conn net.Conn) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	if header[0] != 0x05 || header[1] != 0x01 || header[2] != 0x00 {
		return "", fmt.Errorf("only SOCKS5 CONNECT is supported")
	}
	host, err := readSOCKSHost(conn, header[3])
	if err != nil {
		return "", err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", fmt.Errorf("port zero is invalid")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSOCKSHost(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		var value [4]byte
		if _, err := io.ReadFull(conn, value[:]); err != nil {
			return "", err
		}
		return net.IP(value[:]).String(), nil
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", err
		}
		if length[0] == 0 {
			return "", fmt.Errorf("empty SOCKS domain")
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", err
		}
		return string(value), nil
	case 0x04:
		var value [16]byte
		if _, err := io.ReadFull(conn, value[:]); err != nil {
			return "", err
		}
		return net.IP(value[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS address type")
	}
}

func writeSOCKSReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// socks5ClientHandshake is also used for an explicitly configured upstream
// SOCKS5 proxy. target is normally a concrete authorized IP address.
func socks5ClientHandshake(conn net.Conn, target, username, password string) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	method := byte(0x00)
	if username != "" || password != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		return err
	}
	if selection[0] != 0x05 || selection[1] != method {
		return fmt.Errorf("upstream SOCKS authentication method rejected")
	}
	if method == 0x02 {
		if len(username) > 255 || len(password) > 255 {
			return fmt.Errorf("upstream SOCKS credentials are too long")
		}
		auth := []byte{0x01, byte(len(username))}
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		var result [2]byte
		if _, err := io.ReadFull(conn, result[:]); err != nil {
			return err
		}
		if result[1] != 0x00 {
			return fmt.Errorf("upstream SOCKS authentication failed")
		}
	}
	host, port, err := splitTarget(target)
	if err != nil {
		return err
	}
	request := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		request = append(request, 0x01)
		request = append(request, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		request = append(request, 0x04)
		request = append(request, ip6...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("invalid upstream SOCKS target host")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	portNumber, _ := strconv.Atoi(port)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNumber))
	request = append(request, portBytes[:]...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("upstream SOCKS CONNECT failed with code %d", reply[1])
	}
	if _, err := readSOCKSHost(conn, reply[3]); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}
