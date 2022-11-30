package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const (
	Unauthenticated = 1 << iota
	Authenticated
	Encrypted
)

const (
	AcceptOK = iota
	AcceptFailure
	AcceptInternalError
	AcceptNotSupported
	AcceptPermLimit
	AcceptTempLimit
)

type Timestamp struct {
	Seconds  uint32
	Fraction uint32
}

type ServerGreeting struct {
	Unused    [12]byte
	Modes     uint32
	Challenge [16]byte
	Salt      [16]byte
	Count     uint32
	MBZ       [12]byte
}

type SetupResponse struct {
	Mode     uint32
	KeyID    [80]byte
	Token    [64]byte
	ClientIV [16]byte
}

type ServerStart struct {
	MBZ       [15]byte
	Accept    byte
	ServerIV  [16]byte
	StartTime Timestamp
	MBZ2      [8]byte
}

type RequestSession struct {
	Five          byte
	IPVN          byte
	ConfSender    byte
	ConfReceiver  byte
	Slots         uint32
	Packets       uint32
	SenderPort    uint16
	ReceiverPort  uint16
	SendAddress   uint32
	SendAddress2  [12]byte
	RecvAddress   uint32
	RecvAddress2  [12]byte
	SID           [16]byte
	PaddingLength uint32
	StartTime     Timestamp
	Timeout       uint64
	TypeP         uint32
	MBZ           [8]byte
	HMAC          [16]byte
}

type AcceptSession struct {
	Accept byte
	MBZ    byte
	Port   uint16
	SID    [16]byte
	MBZ2   [12]byte
	HMAC   [16]byte
}

type StartSessions struct {
	Two  byte
	MBZ  [15]byte
	HMAC [16]byte
}

type StartAck struct {
	Accept byte
	MBZ    [15]byte
	HMAC   [16]byte
}

type StopSessions struct {
	Three  byte
	Accept byte
	MBZ    [2]byte
	Number uint32
	MBZ2   [8]byte
}

type TestRequest struct {
	Sequence  uint32
	Timestamp Timestamp
	ErrorEst  uint16
}

type TestResponse struct {
	Sequence        uint32
	Timestamp       Timestamp
	ErrorEst        uint16
	MBZ             [2]byte
	RcvTimestamp    Timestamp
	SenderSequence  uint32
	SenderTimestamp Timestamp
	SenderErrorEst  uint16
	MBZ2            [2]byte
	SenderTTL       byte
}

func serveTwamp(listen string, udp_start uint) error {
	sock, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("Error listening on %s: %s", listen, err)
	}

	glog.Infoln("Listening on", listen)
	defer sock.Close()

	var udp_port = uint16(udp_start)
	for {
		conn, err := sock.Accept()
		if err != nil {
			return fmt.Errorf("Error accepting connection: %s", err)
		}

		go handleClient(conn, udp_port)
		udp_port++
	}
}

func handleClient(conn net.Conn, udp_port uint16) {
	err := serveClient(conn, udp_port)
	if err != nil {
		glog.Error(err)
	}
}

func serveClient(conn net.Conn, udp_port uint16) error {
	defer conn.Close()

	glog.Infoln("Handling control connection from client", conn.RemoteAddr())

	err := sendServerGreeting(conn)
	if err != nil {
		return fmt.Errorf("Error sending greeting: %s", err)
	}

	_, err = receiveSetupResponse(conn)
	if err != nil {
		return fmt.Errorf("Error receiving setup: %s", err)
	}

	err = sendServerStart(conn)
	if err != nil {
		return fmt.Errorf("Error sending start: %s", err)
	}

	_, err = receiveRequestSession(conn)
	if err != nil {
		return fmt.Errorf("Error receiving session: %s", err)
	}

	udp_conn, err := startReflector(udp_port)
	if err != nil {
		return fmt.Errorf("Error starting reflector on port %d: %s", udp_port, err)
	}

	err = sendAcceptSession(conn, udp_port)
	if err != nil {
		return fmt.Errorf("Error sending session accept: %s", err)
	}

	_, err = receiveStartSessions(conn)
	if err != nil {
		return fmt.Errorf("Error receiving start sessions: %s", err)
	}

	test_done := make(chan bool)
	defer close(test_done)
	go handleReflector(udp_conn, test_done)

	err = sendStartAck(conn)
	if err != nil {
		return fmt.Errorf("Error sending start ACK: %s", err)
	}

	_, err = receiveStopSessions(conn)
	if err != nil {
		return fmt.Errorf("Error receiving stop sessions: %s", err)
	}

	glog.Infoln("Finished control connection from client", conn.RemoteAddr())
	return nil
}

func sendServerGreeting(conn net.Conn) error {
	greeting, err := createServerGreeting(Unauthenticated)
	if err != nil {
		return err
	}

	err = sendMessage(conn, greeting)
	if err != nil {
		return err
	}

	return nil
}

func createServerGreeting(modes uint32) (*ServerGreeting, error) {
	greeting := new(ServerGreeting)

	greeting.Modes = modes
	greeting.Count = 1024

	_, err := rand.Read(greeting.Challenge[:])
	if err != nil {
		return nil, err
	}

	_, err = rand.Read(greeting.Salt[:])
	if err != nil {
		return nil, err
	}

	return greeting, nil
}

func sendMessage(conn net.Conn, msg interface{}) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msg)
	if err != nil {
		return err
	}

	size := buf.Len()
	n, err := conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	if size != n {
		return errors.New("Could not send message")
	}

	return nil
}

func receiveSetupResponse(conn net.Conn) (*SetupResponse, error) {
	setup := new(SetupResponse)

	err := receiveMessage(conn, setup)
	if err != nil {
		return nil, err
	}

	if setup.Mode != Unauthenticated {
		err = errors.New("Unsupported setup mode received")
		return nil, err
	}

	return setup, nil
}

func receiveRequestSession(conn net.Conn) (*RequestSession, error) {
	session := new(RequestSession)

	err := receiveMessage(conn, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func receiveStartSessions(conn net.Conn) (*StartSessions, error) {
	msg := new(StartSessions)

	err := receiveMessage(conn, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func receiveStopSessions(conn net.Conn) (*StopSessions, error) {
	msg := new(StopSessions)

	err := receiveMessage(conn, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func receiveMessage(conn net.Conn, msg interface{}) error {
	buf := make([]byte, binary.Size(msg))
	_, err := conn.Read(buf)
	if err != nil {
		return err
	}

	reader := bytes.NewBuffer(buf)
	err = binary.Read(reader, binary.BigEndian, msg)
	if err != nil {
		return err
	}

	return nil
}

func getTimestamp(time time.Time) Timestamp {
	var ts Timestamp

	ts.Seconds = uint32(time.Unix() + 2208988800)

	usec := time.Nanosecond() / 1000
	ts.Fraction = uint32((4294967296 * usec) / 1000000)

	return ts
}

func createServerStart(accept byte) (*ServerStart, error) {
	start := new(ServerStart)

	start.Accept = accept

	ts := getTimestamp(time.Now())
	start.StartTime.Seconds = ts.Seconds
	start.StartTime.Fraction = ts.Fraction

	_, err := rand.Read(start.ServerIV[:])
	if err != nil {
		return nil, err
	}

	return start, nil
}

func sendServerStart(conn net.Conn) error {
	start, err := createServerStart(AcceptOK)
	if err != nil {
		return err
	}

	err = sendMessage(conn, start)
	if err != nil {
		return err
	}

	return nil
}

func createAcceptSession(accept byte, port uint16) (*AcceptSession, error) {
	msg := new(AcceptSession)

	msg.Accept = accept
	msg.Port = port
	_, err := rand.Read(msg.SID[:])
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func sendAcceptSession(conn net.Conn, udp_port uint16) error {
	msg, err := createAcceptSession(AcceptOK, udp_port)
	if err != nil {
		return err
	}

	err = sendMessage(conn, msg)
	if err != nil {
		return err
	}

	return nil
}

func createStartAck(accept byte) (*StartAck, error) {
	msg := new(StartAck)

	msg.Accept = accept

	return msg, nil
}

func sendStartAck(conn net.Conn) error {
	msg, err := createStartAck(AcceptOK)
	if err != nil {
		return err
	}

	err = sendMessage(conn, msg)
	if err != nil {
		return err
	}

	return nil
}

func createTestResponse(buf []byte, seq uint32, req_len int) ([]byte, error) {
	req := new(TestRequest)
	reader := bytes.NewBuffer(buf)
	err := binary.Read(reader, binary.BigEndian, req)
	if err != nil {
		return nil, err
	}
	received := time.Now()

	resp := new(TestResponse)
	resp.SenderSequence = req.Sequence
	resp.SenderTimestamp = req.Timestamp
	resp.SenderErrorEst = req.ErrorEst
	resp.SenderTTL = 255

	resp.Sequence = seq
	resp.RcvTimestamp = getTimestamp(received)
	resp.ErrorEst = createErrorEstimate()

	writer := new(bytes.Buffer)
	resp.Timestamp = getTimestamp(time.Now())
	err = binary.Write(writer, binary.BigEndian, resp)
	if err != nil {
		return nil, err
	}

	if writer.Len() < req_len {
		padding := make([]byte, req_len-writer.Len())
		_, err := writer.Write(padding)
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func createErrorEstimate() uint16 {
	var estimate uint16 = 0x3FFF

	var buf syscall.Timex
	_, err := syscall.Adjtimex(&buf)
	if err != nil {
		return estimate
	}

	multiplier := buf.Esterror
	multiplier <<= 32
	multiplier /= 1000000

	var scale uint16
	for multiplier >= 0xFF {
		scale++
		multiplier >>= 1
	}

	estimate = 1 << 15
	estimate |= scale << 8
	estimate |= uint16(multiplier & 0xFF)

	return estimate
}

func startReflector(udp_port uint16) (*net.UDPConn, error) {
	listen := ":" + strconv.Itoa(int(udp_port))
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func handleReflector(conn *net.UDPConn, test_done chan bool) {
	err := runReflector(conn, test_done)
	if err != nil {
		glog.Error(err)
	}
}

func runReflector(conn *net.UDPConn, test_done chan bool) error {
	var seq uint32 = 0
	buf := make([]byte, 10240)
	timeout := 10 * time.Second
	defer conn.Close()

	glog.Infoln("Handling test session on port", conn.LocalAddr())
	for {
		err := conn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return fmt.Errorf("Error setting test deadline: %s", err)
		}

		req_len, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				select {
				case <-test_done:
					glog.Infoln("Finished test session on port", conn.LocalAddr())
					return nil
				default:
					glog.V(2).Infoln("Timeout waiting for test packet:", err)
					continue
				}
			}

			return fmt.Errorf("Error receiving test packet: %s", err)
		}

		response, err := createTestResponse(buf, seq, req_len)
		if err != nil {
			return fmt.Errorf("Error creating test response: %s", err)
		}

		_, err = conn.WriteToUDP(response, addr)
		if err != nil {
			return fmt.Errorf("Error sending test reponse: %s", err)
		}

		seq++
	}
}

func cleanup() {
	glog.Flush()
}

func handleSignals(c chan os.Signal) {
	sig := <-c
	glog.Infoln("Exiting, got signal:", sig)

	cleanup()
	os.Exit(0)
}

func setupSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go handleSignals(c)
}

func main() {
	listenPtr := flag.String("listen", "localhost:2000", "listen address")
	udpStart := flag.Uint("udp-start", 2000, "initial UDP port for tests")
	flag.Parse()

	setupSignals()

	err := serveTwamp(*listenPtr, *udpStart)
	if err != nil {
		glog.Error(err)
	}
	cleanup()
}
