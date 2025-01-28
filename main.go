package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"proxy-server/internal/proxy"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var logger *log.Logger

var (
	port     = flag.String("port", getEnvOrDefault("PROXY_PORT", "8080"), "Port to run the proxy server on")
	username = flag.String("username", getEnvOrDefault("PROXY_USERNAME", "admin"), "Username for basic auth")
	password = flag.String("password", getEnvOrDefault("PROXY_PASSWORD", "password"), "Password for basic auth")
)

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func init() {
	
	logFile, err := os.OpenFile("tui_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open TUI log file: %v\n", err)
		os.Exit(1)
	}
	logger = log.New(logFile, "[TUI] ", log.LstdFlags|log.Lshortfile)
}

type model struct {
	proxy          *proxy.ProxyServer
	spinner        spinner.Model
	table          table.Model
	quitting       bool
	err            error
	bandwidthUsage int64
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginLeft(2)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86"))

	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))
)

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	columns := []table.Column{
		{Title: "URL", Width: 40},
		{Title: "Visits", Width: 10},
		{Title: "Data", Width: 15},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	
	styles := table.DefaultStyles()
	styles.Header = styles.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false).
		Padding(0, 1)

	styles.Selected = styles.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	styles.Cell = styles.Cell.
		Padding(0, 1)

	t.SetStyles(styles)

	
	proxyConfig := proxy.Config{
		Port:     *port,
		Username: *username,
		Password: *password,
	}

	return model{
		proxy:   proxy.NewProxyServer(proxyConfig),
		spinner: s,
		table:   t,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tea.Every(500*time.Millisecond, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}),
	)
}

type tickMsg time.Time

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			if m.proxy.IsRunning() {
				logger.Printf("Stopping proxy server")
				if err := m.proxy.Stop(); err != nil {
					if err == proxy.ErrServerNotRunning {
						logger.Printf("Server already stopped")
					} else {
						m.err = fmt.Errorf("failed to stop proxy: %v", err)
						logger.Printf("Error stopping proxy: %v", err)
					}
				}
			}
			return m, tea.Quit
		case "s":
			if m.proxy.IsRunning() {
				logger.Printf("Stopping proxy server")
				if err := m.proxy.Stop(); err != nil {
					if err == proxy.ErrServerNotRunning {
						logger.Printf("Server already stopped")
					} else {
						m.err = fmt.Errorf("failed to stop proxy: %v", err)
						logger.Printf("Error stopping proxy: %v", err)
					}
				}
			} else {
				logger.Printf("Starting proxy server")
				
				errChan := make(chan error, 1)
				go func() {
					if err := m.proxy.Start(); err != nil {
						if err == proxy.ErrServerRunning {
							logger.Printf("Server already running")
						} else if err != http.ErrServerClosed {
							errChan <- err
						}
					}
					close(errChan)
				}()

				
				select {
				case err := <-errChan:
					if err != nil {
						m.err = fmt.Errorf("failed to start proxy: %v", err)
						logger.Printf("Error starting proxy: %v", err)
					}
				case <-time.After(100 * time.Millisecond):
					
					if err := m.proxy.WaitForStart(1 * time.Second); err != nil {
						if err == proxy.ErrStartTimeout {
							m.err = fmt.Errorf("proxy server timed out while starting")
						} else {
							m.err = fmt.Errorf("proxy server failed to start: %v", err)
						}
						logger.Printf("Error waiting for proxy start: %v", err)
					} else {
						logger.Printf("Proxy server started successfully")
					}
				}
			}
		case "tab", "shift+tab":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		}

	case tickMsg:
		if m.proxy.IsRunning() {
			logger.Printf("Tick: getting metrics")
			bandwidthUsage, metrics := m.proxy.GetMetrics()
			m.bandwidthUsage = bandwidthUsage
			logger.Printf("Got metrics - Bandwidth: %d bytes, Metrics: %v", bandwidthUsage, metrics)

			
			type siteMetrics struct {
				url       string
				visits    int
				dataBytes int64
			}
			metricSlice := make([]siteMetrics, 0, len(metrics))
			for url, m := range metrics {
				metricSlice = append(metricSlice, siteMetrics{
					url:       url,
					visits:    m.Visits,
					dataBytes: m.DataBytes,
				})
			}

			
			sort.Slice(metricSlice, func(i, j int) bool {
				return metricSlice[i].visits > metricSlice[j].visits
			})

			
			rows := make([]table.Row, 0, len(metricSlice))
			for _, m := range metricSlice {
				dataSize := formatBytes(m.dataBytes)
				rows = append(rows, []string{
					m.url,
					fmt.Sprintf("%d", m.visits),
					dataSize,
				})
			}
			logger.Printf("Updating table with %d rows: %v", len(rows), rows)
			m.table.SetRows(rows)

			
			return m, tea.Batch(
				m.spinner.Tick,
				tea.Every(500*time.Millisecond, func(t time.Time) tea.Msg {
					return tickMsg(t)
				}),
				func() tea.Msg {
					return tea.KeyMsg{Type: tea.KeyRunes}
				},
			)
		}

		
		return m, tea.Batch(
			m.spinner.Tick,
			tea.Every(500*time.Millisecond, func(t time.Time) tea.Msg {
				return tickMsg(t)
			}),
		)

	case error:
		m.err = msg
		logger.Printf("Error received: %v", msg)
		return m, nil
	}

	
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.err != nil {
		return fmt.Sprintf("\nError: %v\nPress any key to quit\n", m.err)
	}

	var b strings.Builder

	
	b.WriteString(titleStyle.Render("Proxy Server Monitor"))

	
	status := fmt.Sprintf("\n%s Proxy Server Status: %s\n",
		m.spinner.View(),
		statusStyle.Render(getStatus(m.proxy)))
	b.WriteString(status)

	
	bandwidthUsage := float64(m.bandwidthUsage) / (1024 * 1024)
	metrics := fmt.Sprintf("\nBandwidth Usage: %.2f MB\n", bandwidthUsage)
	b.WriteString(metrics)

	
	b.WriteString("\nTop Sites:\n")
	tableStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1)

	
	tableContent := m.table.View()
	if tableContent == "" {
		tableContent = "No sites visited yet"
	}

	
	b.WriteString(tableStyle.Render(tableContent))

	
	controls := "\nPress 's' to start/stop the proxy server • 'tab' to focus/blur table • 'q' to quit\n"
	b.WriteString(controls)

	return b.String()
}

func getStatus(p *proxy.ProxyServer) string {
	if p.IsRunning() {
		return "Running"
	}
	return "Stopped"
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func main() {
	flag.Parse()

	cleanup := func() {
		logger.Printf("Cleaning up resources...")
		if err := logger.Writer().(*os.File).Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err)
		}
	}
	defer cleanup()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Printf("Received shutdown signal")
		cleanup()
		os.Exit(0)
	}()

	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
