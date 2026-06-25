package Plugins

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/killmonday/fscanx/common"
)

type tcpAliveTarget struct {
	host string
	port int
}

type tcpAliveResult struct {
	host string
	port int
}

func TcpAliveScanByChan(inputChan <-chan string, scanPorts string) []string {
	probePorts := buildTcpAliveProbePorts(scanPorts)
	if len(probePorts) == 0 {
		return nil
	}

	common.LogSuccess("[*] TCP存活探测: ports=%s", formatAliveProbePorts(probePorts))

	workers := common.PortScanThreadNum
	if workers < 1 {
		workers = 1
	}
	timeout := common.NmapSingleProbeTimeout
	if timeout <= 0 {
		timeout = time.Duration(common.TcpTimeout) * time.Second
	}

	taskChan := make(chan tcpAliveTarget, workers)
	resultChan := make(chan tcpAliveResult, workers)
	var workerWG sync.WaitGroup
	var aliveHosts sync.Map

	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for target := range taskChan {
				if _, ok := aliveHosts.Load(target.host); ok {
					continue
				}
				if probeTcpAlive(target.host, target.port, timeout) {
					if _, loaded := aliveHosts.LoadOrStore(target.host, struct{}{}); !loaded {
						resultChan <- tcpAliveResult{host: target.host, port: target.port}
					}
				}
			}
		}()
	}

	go func() {
		for host := range inputChan {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			for _, port := range probePorts {
				if _, ok := aliveHosts.Load(host); ok {
					break
				}
				taskChan <- tcpAliveTarget{host: host, port: port}
			}
		}
		close(taskChan)
		workerWG.Wait()
		close(resultChan)
	}()

	var aliveList []string
	for result := range resultChan {
		aliveList = append(aliveList, result.host)
		recordTcpAliveHost(result.host)
		common.LogSuccess("[*] %s 存活 (协议: TCP/%d)", result.host, result.port)
	}
	sort.Strings(aliveList)
	return aliveList
}

func buildTcpAliveProbePorts(_ string) []int {
	portSet := make(map[int]struct{})
	addPorts := func(ports []int) {
		for _, port := range ports {
			if port > 0 && port <= 65535 {
				portSet[port] = struct{}{}
			}
		}
	}

	addPorts(common.ParsePort(common.AliveProbePorts))

	probePorts := make([]int, 0, len(portSet))
	for port := range portSet {
		probePorts = append(probePorts, port)
	}
	sort.Ints(probePorts)
	return probePorts
}

func formatAliveProbePorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	limit := len(ports)
	suffix := ""
	if limit > 16 {
		limit = 16
		suffix = fmt.Sprintf(",...(+%d)", len(ports)-limit)
	}

	items := make([]string, 0, limit)
	for _, port := range ports[:limit] {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ",") + suffix
}

func recordTcpAliveHost(host string) {
	index := strings.LastIndex(host, ".")
	if index == -1 {
		return
	}
	ipc := host[:index]
	num, ok := AliveIpCPrefix.Load(ipc)
	if ok {
		AliveIpCPrefix.Store(ipc, num.(uint16)+1)
		return
	}
	AliveIpCPrefix.Store(ipc, uint16(1))
}

func probeTcpAlive(host string, port int, timeout time.Duration) bool {
	conn, err := dialTcpAlive(host, port, timeout)
	if err != nil || conn == nil {
		return false
	}

	if common.Socks5Proxy == "" {
		closeTcpAliveConn(conn)
		return true
	}

	if probeTcpAliveThroughSocks(conn, host, port, timeout) {
		closeTcpAliveConn(conn)
		return true
	}
	closeTcpAliveConn(conn)

	return false
}

func probeTcpAliveThroughSocks(conn net.Conn, host string, port int, timeout time.Duration) bool {
	switch port {
	case 80, 8000, 8008, 8080, 8081, 8088, 8089, 8888:
		return probeHTTPAlive(conn, host, timeout)
	case 443, 8443:
		return probeTLSAlive(conn, host, timeout)
	case 445:
		return writeAndReadTcpAliveResponse(conn, smb2_negotiateProtocolRequest, timeout)
	}

	if tcpAliveCanTrustPassiveRead(port) && readTcpAliveResponse(conn, timeout) {
		return true
	}

	for _, payload := range tcpAliveStrictPayloads(port) {
		conn, err := dialTcpAlive(host, port, timeout)
		if err != nil || conn == nil {
			continue
		}
		if writeAndReadTcpAliveResponse(conn, payload, timeout) {
			closeTcpAliveConn(conn)
			return true
		}
		closeTcpAliveConn(conn)
	}
	return false
}

func probeHTTPAlive(conn net.Conn, host string, timeout time.Duration) bool {
	payload := []byte(fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: fscanx-alive\r\nConnection: close\r\n\r\n", host))
	writeTimeout := timeout
	if writeTimeout <= 0 || writeTimeout > 2*time.Second {
		writeTimeout = 2 * time.Second
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(payload); err != nil {
		return false
	}

	readTimeout := timeout
	if readTimeout <= 0 || readTimeout > 2*time.Second {
		readTimeout = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	return strings.HasPrefix(string(buf[:n]), "HTTP/")
}

func probeTLSAlive(conn net.Conn, host string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = time.Duration(common.TcpTimeout) * time.Second
	}
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	err := tlsConn.Handshake()
	if err == nil {
		return true
	}

	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "remote error: tls:") {
		return true
	}
	return false
}

func dialTcpAlive(host string, port int, timeout time.Duration) (net.Conn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: time.Second}

	localIP := net.ParseIP("0.0.0.0")
	if common.Iface != "" {
		localIP = net.ParseIP(common.Iface)
	}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}

	if common.Socks5Proxy == "" {
		return dialer.Dial("tcp4", address)
	}

	proxyDialer, err := common.Socks5Dailer(dialer)
	if err != nil {
		return nil, err
	}
	return proxyDialer.Dial("tcp4", address)
}

func readTcpAliveResponse(conn net.Conn, timeout time.Duration) bool {
	readTimeout := timeout
	if readTimeout <= 0 || readTimeout > 2*time.Second {
		readTimeout = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

func writeAndReadTcpAliveResponse(conn net.Conn, payload []byte, timeout time.Duration) bool {
	writeTimeout := timeout
	if writeTimeout <= 0 || writeTimeout > 2*time.Second {
		writeTimeout = 2 * time.Second
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	return readTcpAliveResponse(conn, timeout)
}

func closeTcpAliveConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()
}

func tcpAliveCanTrustPassiveRead(port int) bool {
	switch port {
	case 21, 22, 25, 110, 143, 220, 587, 993, 995:
		return true
	default:
		return false
	}
}

func tcpAliveStrictPayloads(port int) [][]byte {
	switch port {
	case 445:
		if len(smb2_negotiateProtocolRequest) == 0 {
			return nil
		}
		return [][]byte{smb2_negotiateProtocolRequest}
	case 3389:
		return [][]byte{strictSocksProbePayloads[2]}
	case 6379:
		return [][]byte{strictSocksProbePayloads[1]}
	case 80, 443, 8000, 8008, 8080, 8081, 8088, 8089, 8443, 8888:
		return nil
	default:
		payloads := make([][]byte, 0, len(strictSocksProbePayloads))
		payloads = append(payloads, strictSocksProbePayloads[1:]...)
		if len(smb2_negotiateProtocolRequest) > 0 {
			payloads = append(payloads, smb2_negotiateProtocolRequest)
		}
		return payloads
	}
}
