package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// List of hop-by-hop headers to be removed
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

type SiteMetrics struct {
	Visits    int
	DataBytes int64
}

type circuitBreaker struct {
	failures    int
	lastFailure time.Time
	mu          sync.RWMutex
}

type authAttempt struct {
	lastAttempt time.Time
	attempts    int
}

type ProxyServer struct {
	mu             sync.RWMutex
	port           string
	username       string
	password       string
	bandwidthUsage int64
	siteMetrics    map[string]*SiteMetrics
	server         *http.Server
	isRunning      bool
	startupDone    chan struct{}
	logger         *log.Logger
	client         *http.Client
	breakers       map[string]*circuitBreaker
	authAttempts   map[string]*authAttempt // IP -> attempts
}

// Error variables for common errors
var (
	ErrServerRunning    = fmt.Errorf("server already running")
	ErrServerNotRunning = fmt.Errorf("server not running")
	ErrStartTimeout     = fmt.Errorf("timeout waiting for server to start")
)

// Configuration constants
const (
	maxBodySize         = 10 * 1024 * 1024 // 10MB
	maxRetries          = 3
	retryDelay          = 100 * time.Millisecond
	maxFailures         = 5
	circuitResetTimeout = 30 * time.Second
	maxAuthAttempts     = 5               // Max auth attempts per window
	authWindowDuration  = 5 * time.Minute // Window duration for auth attempts
)

// Config holds the configuration for ProxyServer
type Config struct {
	Port     string
	Username string
	Password string
}

// NewProxyServer creates a new proxy server with the given configuration
func NewProxyServer(cfg Config) *ProxyServer {
	// Create a log file
	logFile, err := os.OpenFile("proxy_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file: %v", err))
	}

	logger := log.New(logFile, "[PROXY] ", log.LstdFlags|log.Lshortfile)

	// Configure transport with connection pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       10,
		DisableKeepAlives:     false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &ProxyServer{
		port:         cfg.Port,
		username:     cfg.Username,
		password:     cfg.Password,
		siteMetrics:  make(map[string]*SiteMetrics),
		startupDone:  make(chan struct{}),
		logger:       logger,
		client:       client,
		breakers:     make(map[string]*circuitBreaker),
		authAttempts: make(map[string]*authAttempt),
	}
}

func (s *ProxyServer) Start() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return ErrServerRunning
	}

	// Create a new channel for this start attempt
	s.startupDone = make(chan struct{})
	startupDone := s.startupDone // Keep a reference to this channel

	s.server = &http.Server{
		Addr:    ":" + s.port,
		Handler: http.HandlerFunc(s.handleRequest),
	}
	s.isRunning = true
	s.mu.Unlock()

	// Try to start listening on the port
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on port %s: %v", s.port, err)
	}

	// Signal that we're ready to accept connections
	close(startupDone)

	// Start serving
	err = s.server.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *ProxyServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return ErrServerNotRunning
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	s.isRunning = false
	return err
}

func (s *ProxyServer) WaitForStart(timeout time.Duration) error {
	select {
	case <-s.startupDone:
		return nil
	case <-time.After(timeout):
		return ErrStartTimeout
	}
}

func (s *ProxyServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

func (s *ProxyServer) GetMetrics() (int64, map[string]*SiteMetrics) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a copy of the site metrics map
	metrics := make(map[string]*SiteMetrics)
	for k, v := range s.siteMetrics {
		metrics[k] = &SiteMetrics{
			Visits:    v.Visits,
			DataBytes: v.DataBytes,
		}
	}

	s.logger.Printf("GetMetrics called - Bandwidth: %d bytes, Metrics: %+v", s.bandwidthUsage, metrics)
	return s.bandwidthUsage, metrics
}

func (s *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("Received request: %s %s from %s", r.Method, r.URL, r.RemoteAddr)

	if !s.authenticate(r) {
		s.logger.Printf("Authentication failed for request from %s", r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	s.logger.Printf("Authentication successful for request from %s", r.RemoteAddr)

	if r.Method == http.MethodConnect {
		s.handleHTTPS(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

func (s *ProxyServer) checkAuthRate(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	attempt, exists := s.authAttempts[ip]

	if !exists {
		s.authAttempts[ip] = &authAttempt{
			lastAttempt: now,
			attempts:    1,
		}
		return true
	}

	// Reset if window has expired
	if now.Sub(attempt.lastAttempt) > authWindowDuration {
		attempt.attempts = 1
		attempt.lastAttempt = now
		return true
	}

	// Check if too many attempts
	if attempt.attempts >= maxAuthAttempts {
		s.logger.Printf("Rate limit exceeded for IP %s", ip)
		return false
	}

	// Update attempt count
	attempt.attempts++
	attempt.lastAttempt = now
	return true
}

func (s *ProxyServer) authenticate(r *http.Request) bool {
	// Get client IP
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Check rate limit
	if !s.checkAuthRate(ip) {
		return false
	}

	// Check if using HTTPS
	if r.TLS == nil {
		s.logger.Printf("Warning: Authentication over non-HTTPS connection from %s", ip)
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	username, password := credentials[0], credentials[1]
	return username == s.username && password == s.password
}

func shouldRetry(err error, statusCode int) bool {
	if err != nil {
		// Retry on network errors
		if netErr, ok := err.(net.Error); ok {
			return netErr.Temporary()
		}
		return false
	}
	// Retry on 5xx errors except 501 Not Implemented
	return statusCode >= 500 && statusCode != 501
}

func (s *ProxyServer) getCircuitBreaker(host string) *circuitBreaker {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cb, exists := s.breakers[host]; exists {
		return cb
	}

	cb := &circuitBreaker{}
	s.breakers[host] = cb
	return cb
}

func (cb *circuitBreaker) isOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.failures >= maxFailures {
		if time.Since(cb.lastFailure) > circuitResetTimeout {
			// Circuit has cooled down, allow one request through
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.failures = 0
			cb.mu.Unlock()
			cb.mu.RLock()
			return false
		}
		return true
	}
	return false
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
}

func (s *ProxyServer) doWithRetry(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	cb := s.getCircuitBreaker(host)

	if cb.isOpen() {
		return nil, fmt.Errorf("circuit breaker open for %s", host)
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			s.logger.Printf("Retry attempt %d for %s", attempt, req.URL)
			time.Sleep(retryDelay * time.Duration(attempt))
		}

		// Create a new request for each attempt
		retryReq := req.Clone(req.Context())
		if req.Body != nil {
			// We can't reuse the body, so we need to skip retries
			s.logger.Printf("Request has body, skipping retries")
			resp, err = s.client.Do(req)
			if err != nil {
				cb.recordFailure()
				return nil, err
			}
			cb.recordSuccess()
			return resp, nil
		}

		resp, err = s.client.Do(retryReq)
		if err != nil {
			if !shouldRetry(err, 0) {
				cb.recordFailure()
				return nil, err
			}
			continue
		}

		if !shouldRetry(nil, resp.StatusCode) {
			cb.recordSuccess()
			return resp, nil
		}

		resp.Body.Close()
	}

	// Record failure after max retries
	cb.recordFailure()

	// Return the last response or error
	if resp != nil {
		return resp, nil
	}
	return nil, fmt.Errorf("max retries reached: %v", err)
}

func (s *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a new request to forward
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add body size limit if Content-Length is set
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// If no Content-Length, use LimitReader to enforce max size
	if r.ContentLength == -1 {
		r.Body = io.NopCloser(io.LimitReader(r.Body, maxBodySize))
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		outReq.Header.Del(h)
	}

	// Make the request with retry
	resp, err := s.doWithRetry(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check response size
	if resp.ContentLength > maxBodySize {
		http.Error(w, "Response body too large", http.StatusBadGateway)
		return
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body with size limit
	written, err := io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		s.logger.Printf("Error copying response: %v", err)
		return
	}

	// Update the visit with actual data received
	s.trackVisit(r.Host, written)
}

func (s *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Connect to the target host with timeout
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		s.logger.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	// Set read/write timeouts on both connections
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(32 * 1024)
		tcpConn.SetWriteBuffer(32 * 1024)
	}
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(32 * 1024)
		tcpConn.SetWriteBuffer(32 * 1024)
	}

	clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	// Create channels to collect bytes written in both directions
	bytesWrittenChan := make(chan int64, 2)
	doneChan := make(chan bool, 2)

	// Start bidirectional copy with timeout
	go func() {
		// Copy from client to target
		written, err := io.Copy(targetConn, clientConn)
		if err != nil {
			s.logger.Printf("Error copying to target: %v", err)
			bytesWrittenChan <- 0
		} else {
			bytesWrittenChan <- written
		}
		doneChan <- true
	}()

	go func() {
		// Copy from target to client
		written, err := io.Copy(clientConn, targetConn)
		if err != nil {
			s.logger.Printf("Error copying to client: %v", err)
			bytesWrittenChan <- 0
		} else {
			bytesWrittenChan <- written
		}
		doneChan <- true
	}()

	// Wait for both copies to complete or timeout
	timeoutChan := time.After(5 * time.Minute)
	var totalBytes int64

	for i := 0; i < 2; i++ {
		select {
		case written := <-bytesWrittenChan:
			totalBytes += written
		case <-timeoutChan:
			s.logger.Printf("HTTPS tunnel timed out")
			return
		case <-doneChan:
			continue
		}
	}

	if totalBytes > 0 {
		s.trackVisit(r.Host, totalBytes)
	}
}

func (s *ProxyServer) trackVisit(host string, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	metrics, exists := s.siteMetrics[host]
	if !exists {
		metrics = &SiteMetrics{}
		s.siteMetrics[host] = metrics
	}

	// Only increment visits if we actually received data
	if bytes > 0 {
		metrics.Visits++
	}
	metrics.DataBytes += bytes
	s.bandwidthUsage += bytes

	s.logger.Printf("Updated metrics for %s: visits=%d, data=%d bytes", host, metrics.Visits, metrics.DataBytes)
}
