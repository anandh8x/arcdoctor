package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/anandh8x/arcdoctor/internal/doctor"
	"github.com/anandh8x/arcdoctor/internal/redact"
)

type Diagnoser interface {
	Diagnose(context.Context, doctor.Request) (doctor.Report, error)
}

type Factory func(string) Diagnoser

type FileReader func(string) ([]byte, error)

type Exporter func(doctor.Report) (string, error)

type screen int

const (
	homeScreen screen = iota
	formScreen
	runningScreen
	resultScreen
)

type diagnosisChoice struct {
	title       string
	description string
	kind        doctor.RequestKind
}

var diagnosisChoices = []diagnosisChoice{
	{
		title:       "Environment check",
		description: "Verify Arc Testnet identity, block freshness, and endpoint latency.",
		kind:        doctor.NetworkCheck,
	},
	{
		title:       "Address inspection",
		description: "Inspect balance, nonce, bytecode, and the ArcScan address.",
		kind:        doctor.AddressCheck,
	},
	{
		title:       "Transaction inspection",
		description: "Classify execution and decode calldata or revert evidence.",
		kind:        doctor.TransactionCheck,
	},
	{
		title:       "Deployment validation",
		description: "Check a manifest or Foundry broadcast against Arc Testnet.",
		kind:        doctor.DeploymentCheck,
	},
}

type formField struct {
	label string
	input textinput.Model
}

type diagnosisMsg struct {
	report doctor.Report
	err    error
}

type exportMsg struct {
	path string
	err  error
}

type Model struct {
	factory  Factory
	readFile FileReader
	export   Exporter

	screen   screen
	cursor   int
	selected diagnosisChoice
	fields   []formField
	focus    int
	width    int
	height   int

	spinner  spinner.Model
	viewport viewport.Model

	report      doctor.Report
	err         error
	status      string
	cancel      context.CancelFunc
	lastRequest doctor.Request
	lastRPC     string
}

func NewModel(factory Factory, readFile FileReader, export Exporter) Model {
	if readFile == nil {
		readFile = os.ReadFile
	}
	if export == nil {
		export = ExportReport
	}
	progress := spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#B8DFA6"))),
	)
	resultViewport := viewport.New(
		viewport.WithWidth(76),
		viewport.WithHeight(20),
	)
	resultViewport.SoftWrap = true

	return Model{
		factory:  factory,
		readFile: readFile,
		export:   export,
		screen:   homeScreen,
		width:    80,
		height:   28,
		spinner:  progress,
		viewport: resultViewport,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = max(32, message.Width)
		m.height = max(12, message.Height)
		m.resize()
		return m, nil
	case diagnosisMsg:
		m.cancel = nil
		m.report = message.report
		m.err = message.err
		m.screen = resultScreen
		m.status = ""
		m.viewport.SetContent(formatReport(message.report, message.err))
		m.viewport.GotoTop()
		return m, nil
	case exportMsg:
		if message.err != nil {
			m.status = "Export failed: " + redact.String(message.err.Error())
		} else {
			m.status = "Saved sanitized report to " + message.path
		}
		return m, nil
	case tea.KeyPressMsg:
		if message.String() == "ctrl+c" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
	}

	switch m.screen {
	case homeScreen:
		return m.updateHome(message)
	case formScreen:
		return m.updateForm(message)
	case runningScreen:
		return m.updateRunning(message)
	case resultScreen:
		return m.updateResult(message)
	default:
		return m, nil
	}
}

func (m Model) updateHome(message tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		m.cursor = max(0, m.cursor-1)
	case "down", "j":
		m.cursor = min(len(diagnosisChoices)-1, m.cursor+1)
	case "enter":
		m.selected = diagnosisChoices[m.cursor]
		m.configureForm()
		m.screen = formScreen
		return m, m.focusField(0)
	}
	return m, nil
}

func (m Model) updateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			m.blurFields()
			m.screen = homeScreen
			m.status = ""
			return m, nil
		case "tab", "down":
			return m, m.focusField((m.focus + 1) % len(m.fields))
		case "shift+tab", "up":
			return m, m.focusField((m.focus - 1 + len(m.fields)) % len(m.fields))
		case "enter":
			if m.focus < len(m.fields)-1 {
				return m, m.focusField(m.focus + 1)
			}
			return m.beginDiagnosis()
		}
	}

	var command tea.Cmd
	m.fields[m.focus].input, command = m.fields[m.focus].input.Update(message)
	return m, command
}

func (m Model) updateRunning(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok && key.String() == "esc" {
		if m.cancel != nil {
			m.cancel()
			m.status = "Cancelling diagnosis..."
		}
		return m, nil
	}
	var command tea.Cmd
	m.spinner, command = m.spinner.Update(message)
	return m, command
}

func (m Model) updateResult(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "q":
			return m, tea.Quit
		case "esc", "b":
			m.screen = homeScreen
			m.status = ""
			return m, nil
		case "r":
			return m.beginDiagnosis()
		case "e":
			m.status = "Exporting sanitized report..."
			return m, exportCommand(m.export, m.report)
		}
	}
	var command tea.Cmd
	m.viewport, command = m.viewport.Update(message)
	return m, command
}

func (m Model) beginDiagnosis() (tea.Model, tea.Cmd) {
	request, rpcURL, err := m.buildRequest()
	if err != nil {
		m.screen = resultScreen
		m.err = err
		m.report = doctor.Report{}
		m.viewport.SetContent(formatReport(doctor.Report{}, err))
		return m, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.lastRequest = request
	m.lastRPC = rpcURL
	m.screen = runningScreen
	m.status = "Collecting public Arc evidence..."
	return m, tea.Batch(
		m.spinner.Tick,
		diagnoseCommand(ctx, m.factory, rpcURL, request),
	)
}

func (m Model) buildRequest() (doctor.Request, string, error) {
	values := make([]string, len(m.fields))
	for index := range m.fields {
		values[index] = strings.TrimSpace(m.fields[index].input.Value())
	}

	switch m.selected.kind {
	case doctor.NetworkCheck:
		return doctor.Request{
			Kind:          doctor.NetworkCheck,
			WalletAddress: values[0],
		}, defaultRPC(values[1]), nil
	case doctor.AddressCheck:
		if values[0] == "" {
			return doctor.Request{}, "", fmt.Errorf("address is required")
		}
		return doctor.Request{
			Kind:   doctor.AddressCheck,
			Target: values[0],
		}, defaultRPC(values[1]), nil
	case doctor.TransactionCheck:
		if values[0] == "" {
			return doctor.Request{}, "", fmt.Errorf("transaction hash is required")
		}
		abiInputs, err := m.loadABIs(values[1])
		if err != nil {
			return doctor.Request{}, "", err
		}
		return doctor.Request{
			Kind:   doctor.TransactionCheck,
			Target: values[0],
			ABIs:   abiInputs,
		}, defaultRPC(values[2]), nil
	case doctor.DeploymentCheck:
		if values[0] == "" {
			return doctor.Request{}, "", fmt.Errorf("deployment manifest path is required")
		}
		manifestPath, err := filepath.Abs(values[0])
		if err != nil {
			return doctor.Request{}, "", fmt.Errorf("resolve manifest path: %w", err)
		}
		data, err := m.readFile(manifestPath)
		if err != nil {
			return doctor.Request{}, "", fmt.Errorf("read deployment manifest: %w", err)
		}
		artifacts, err := parseOverrides(values[1])
		if err != nil {
			return doctor.Request{}, "", err
		}
		return doctor.Request{
			Kind: doctor.DeploymentCheck,
			Deployment: &doctor.DeploymentInput{
				Name:      filepath.Base(manifestPath),
				BaseDir:   filepath.Dir(manifestPath),
				Data:      data,
				Artifacts: artifacts,
			},
		}, defaultRPC(values[2]), nil
	default:
		return doctor.Request{}, "", fmt.Errorf("unsupported diagnosis")
	}
}

func (m Model) loadABIs(value string) ([]doctor.ABIInput, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	paths := strings.Split(value, ",")
	inputs := make([]doctor.ABIInput, 0, len(paths))
	for _, rawPath := range paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		data, err := m.readFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ABI %q: %w", filepath.Base(path), err)
		}
		inputs = append(inputs, doctor.ABIInput{
			Name: filepath.Base(path),
			Data: data,
		})
	}
	return inputs, nil
}

func (m *Model) configureForm() {
	newInput := func(placeholder, value string) textinput.Model {
		input := textinput.New()
		input.Placeholder = placeholder
		input.Prompt = "  "
		input.CharLimit = 4096
		input.SetWidth(max(24, m.width-10))
		input.SetValue(value)
		return input
	}

	switch m.selected.kind {
	case doctor.NetworkCheck:
		m.fields = []formField{
			{
				label: "Wallet address",
				input: newInput("optional public 0x address", ""),
			},
			{
				label: "RPC URL",
				input: newInput(doctor.DefaultArcTestnetRPC, doctor.DefaultArcTestnetRPC),
			},
		}
	case doctor.AddressCheck:
		m.fields = []formField{
			{label: "Address", input: newInput("0x...", "")},
			{
				label: "RPC URL",
				input: newInput(doctor.DefaultArcTestnetRPC, doctor.DefaultArcTestnetRPC),
			},
		}
	case doctor.TransactionCheck:
		m.fields = []formField{
			{label: "Transaction hash", input: newInput("0x...", "")},
			{
				label: "ABI or artifact paths",
				input: newInput("optional, comma-separated", ""),
			},
			{
				label: "RPC URL",
				input: newInput(doctor.DefaultArcTestnetRPC, doctor.DefaultArcTestnetRPC),
			},
		}
	case doctor.DeploymentCheck:
		m.fields = []formField{
			{
				label: "Manifest or Foundry broadcast",
				input: newInput("./deployments/arc-testnet.json", ""),
			},
			{
				label: "Artifact overrides",
				input: newInput("optional Name=path, comma-separated", ""),
			},
			{
				label: "RPC URL",
				input: newInput(doctor.DefaultArcTestnetRPC, doctor.DefaultArcTestnetRPC),
			},
		}
	}
	m.focus = 0
	m.status = ""
	m.resize()
}

func (m *Model) focusField(index int) tea.Cmd {
	m.focus = index
	var commands []tea.Cmd
	for fieldIndex := range m.fields {
		if fieldIndex == index {
			commands = append(commands, m.fields[fieldIndex].input.Focus())
		} else {
			m.fields[fieldIndex].input.Blur()
		}
	}
	return tea.Batch(commands...)
}

func (m *Model) blurFields() {
	for index := range m.fields {
		m.fields[index].input.Blur()
	}
}

func (m *Model) resize() {
	contentWidth := max(28, m.width-6)
	for index := range m.fields {
		m.fields[index].input.SetWidth(max(20, contentWidth-6))
	}
	m.viewport.SetWidth(contentWidth)
	m.viewport.SetHeight(max(6, m.height-10))
}

func (m Model) View() tea.View {
	var content string
	switch m.screen {
	case homeScreen:
		content = m.homeView()
	case formScreen:
		content = m.formView()
	case runningScreen:
		content = m.runningView()
	case resultScreen:
		content = m.resultView()
	}

	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m Model) homeView() string {
	var builder strings.Builder
	builder.WriteString(titleStyle.Render("ARC DOCTOR"))
	builder.WriteString("\n")
	builder.WriteString(subtitleStyle.Render("Evidence-based diagnostics for Arc Testnet"))
	builder.WriteString("\n\n")
	builder.WriteString(sectionStyle.Render("Choose a diagnosis"))
	builder.WriteString("\n\n")

	for index, choice := range diagnosisChoices {
		marker := "  "
		style := choiceStyle
		if index == m.cursor {
			marker = "> "
			style = selectedChoiceStyle
		}
		builder.WriteString(style.Render(marker + choice.title))
		builder.WriteString("\n")
		builder.WriteString(descriptionStyle.Render("    " + choice.description))
		builder.WriteString("\n\n")
	}
	builder.WriteString(helpStyle.Render("up/down move  enter select  q quit"))
	return frame(m.width, builder.String())
}

func (m Model) formView() string {
	var builder strings.Builder
	builder.WriteString(titleStyle.Render("ARC DOCTOR"))
	builder.WriteString("\n")
	builder.WriteString(sectionStyle.Render(m.selected.title))
	builder.WriteString("\n")
	builder.WriteString(descriptionStyle.Render(m.selected.description))
	builder.WriteString("\n\n")
	for index, field := range m.fields {
		label := field.label
		if index == m.focus {
			label = "> " + label
		} else {
			label = "  " + label
		}
		builder.WriteString(labelStyle.Render(label))
		builder.WriteString("\n")
		builder.WriteString(inputStyle.Render(field.input.View()))
		builder.WriteString("\n\n")
	}
	if m.status != "" {
		builder.WriteString(warningStyle.Render(m.status))
		builder.WriteString("\n\n")
	}
	builder.WriteString(helpStyle.Render("tab move  enter continue or run  esc back  ctrl+c quit"))
	return frame(m.width, builder.String())
}

func (m Model) runningView() string {
	content := strings.Join([]string{
		titleStyle.Render("ARC DOCTOR"),
		"",
		sectionStyle.Render(m.selected.title),
		"",
		m.spinner.View() + " " + m.status,
		"",
		descriptionStyle.Render("Arc Doctor is reading public RPC evidence. It will not sign or send a transaction."),
		"",
		helpStyle.Render("esc cancel  ctrl+c quit"),
	}, "\n")
	return frame(m.width, content)
}

func (m Model) resultView() string {
	var builder strings.Builder
	builder.WriteString(titleStyle.Render("ARC DOCTOR"))
	builder.WriteString("\n")
	builder.WriteString(sectionStyle.Render("Diagnosis result"))
	builder.WriteString("\n\n")
	builder.WriteString(m.viewport.View())
	builder.WriteString("\n")
	if m.status != "" {
		builder.WriteString(statusStyle.Render(m.status))
		builder.WriteString("\n")
	}
	builder.WriteString(helpStyle.Render("up/down scroll  e export  r rerun  b back  q quit"))
	return frame(m.width, builder.String())
}

func diagnoseCommand(
	ctx context.Context,
	factory Factory,
	rpcURL string,
	request doctor.Request,
) tea.Cmd {
	return func() tea.Msg {
		if factory == nil {
			return diagnosisMsg{err: fmt.Errorf("diagnostic factory is unavailable")}
		}
		report, err := factory(rpcURL).Diagnose(ctx, request)
		return diagnosisMsg{report: report, err: err}
	}
}

func exportCommand(export Exporter, report doctor.Report) tea.Cmd {
	return func() tea.Msg {
		path, err := export(report)
		return exportMsg{path: path, err: err}
	}
}

func defaultRPC(value string) string {
	if strings.TrimSpace(value) == "" {
		return doctor.DefaultArcTestnetRPC
	}
	return strings.TrimSpace(value)
}

func parseOverrides(value string) (map[string]string, error) {
	overrides := make(map[string]string)
	if strings.TrimSpace(value) == "" {
		return overrides, nil
	}
	for _, item := range strings.Split(value, ",") {
		name, path, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		path = strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("artifact override must use Name=path")
		}
		if _, exists := overrides[name]; exists {
			return nil, fmt.Errorf("duplicate artifact override for %s", name)
		}
		resolved, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve artifact for %s: %w", name, err)
		}
		overrides[name] = resolved
	}
	return overrides, nil
}

func formatReport(report doctor.Report, diagnosticError error) string {
	var builder strings.Builder
	if diagnosticError != nil {
		builder.WriteString(errorStyle.Render("Arc Doctor could not complete every check"))
		builder.WriteString("\n")
		builder.WriteString(redact.String(diagnosticError.Error()))
		builder.WriteString("\n\n")
	}
	if report.SchemaVersion != 0 {
		builder.WriteString(fmt.Sprintf(
			"Collected %s | ruleset %s | sanitized %t\n",
			report.CollectedAt.Format(time.RFC3339),
			report.Tool.RulesetVersion,
			report.Sanitized,
		))
	}
	if report.Network.ExpectedChainID != 0 {
		builder.WriteString(fmt.Sprintf(
			"Network: Arc Testnet | chain %d | block %d | %.0f ms\n",
			report.Network.ObservedChainID,
			report.Network.BlockNumber,
			report.Network.LatencyMilliseconds,
		))
	}
	if report.Address != nil {
		builder.WriteString(fmt.Sprintf(
			"Address: %s\nType: %s | balance: %s base units | bytecode: %d bytes\n",
			report.Address.Address,
			report.Address.Kind,
			report.Address.BalanceBaseUnits,
			report.Address.CodeSize,
		))
		if report.Address.Proxy != nil {
			builder.WriteString(fmt.Sprintf(
				"Proxy: %s | implementation: %s | beacon: %s\n",
				report.Address.Proxy.Standard,
				report.Address.Proxy.Implementation,
				report.Address.Proxy.Beacon,
			))
		}
	}
	if report.Transaction != nil {
		builder.WriteString(fmt.Sprintf(
			"Transaction: %s\nState: %s | from: %s | to: %s\n",
			report.Transaction.Hash,
			report.Transaction.State,
			report.Transaction.From,
			report.Transaction.To,
		))
		if report.Transaction.Call != nil {
			builder.WriteString("Function: " + report.Transaction.Call.Signature + "\n")
		}
		if report.Transaction.Revert != nil {
			builder.WriteString("Revert: " + report.Transaction.Revert.Signature + "\n")
			builder.WriteString("Raw data: " + report.Transaction.Revert.RawData + "\n")
		}
	}
	if report.Deployment != nil {
		builder.WriteString(fmt.Sprintf(
			"Deployment: %s | %d contracts\n",
			report.Deployment.ManifestName,
			len(report.Deployment.Contracts),
		))
		for _, contract := range report.Deployment.Contracts {
			builder.WriteString(fmt.Sprintf(
				"  %s | %s | %d bytes | artifact %s\n",
				contract.Name,
				contract.Address,
				contract.CodeSize,
				contract.ArtifactComparison,
			))
		}
	}
	if len(report.Findings) == 0 {
		if diagnosticError == nil {
			builder.WriteString("\nNo findings were returned.\n")
		}
		return builder.String()
	}

	builder.WriteString("\nFindings\n")
	for _, finding := range report.Findings {
		builder.WriteString(fmt.Sprintf(
			"\n[%s] %s  %s\n",
			strings.ToUpper(string(finding.Severity)),
			finding.Code,
			finding.Title,
		))
		builder.WriteString(finding.Explanation + "\n")
		builder.WriteString("Confidence: " + string(finding.Confidence) + "\n")
		for _, evidence := range finding.Evidence {
			builder.WriteString("Evidence: " + evidence + "\n")
		}
		for _, action := range finding.SuggestedActions {
			builder.WriteString("Check: " + action + "\n")
		}
	}
	return builder.String()
}

func frame(width int, content string) string {
	contentWidth := max(28, width-6)
	return lipgloss.NewStyle().
		Padding(1, 2).
		Width(contentWidth).
		Render(content)
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#B8DFA6"))
	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A7AAA5"))
	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F3F0E8"))
	choiceStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#D2D4CF"))
	selectedChoiceStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#B8DFA6"))
	descriptionStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#92968F"))
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#B8DFA6"))
	inputStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#4D5C48")).
			Padding(0, 1)
	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#777B75"))
	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#B8DFA6"))
	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0A57A"))
	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#DF8179"))
)

func Run(
	factory Factory,
	readFile FileReader,
	export Exporter,
	input io.Reader,
	output io.Writer,
) error {
	program := tea.NewProgram(
		NewModel(factory, readFile, export),
		tea.WithInput(input),
		tea.WithOutput(output),
	)
	_, err := program.Run()
	return err
}

func ExportReport(report doctor.Report) (string, error) {
	report = doctor.SanitizeReport(report)
	collectedAt := report.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}
	baseName := "arcdoctor-report-" + collectedAt.Format("20060102-150405")

	var lastErr error
	for attempt := 0; attempt < 100; attempt++ {
		name := baseName + ".json"
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d.json", baseName, attempt)
		}
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				lastErr = err
				continue
			}
			return "", err
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("could not allocate report filename: %w", lastErr)
}
