package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

var (
	ErrUnhandledSource = errors.New("ingest: unhandled source type")
	ErrInvalidJSON     = errors.New("ingest: invalid json payload")
	ErrInvalidSyslog   = errors.New("ingest: invalid syslog rfc3164 format")
	ErrEmptyStackTrace = errors.New("ingest: empty stack trace payload")
)

// Parser parses a RawEvent into a NormalizedEvent.
type Parser interface {
	Parse(raw domain.RawEvent) (*domain.NormalizedEvent, error)
}

// MultiParser delegates RawEvents to source-specific parsers based on RawEvent.Source.
type MultiParser struct {
	jsonParser       *JSONParser
	syslogParser     *SyslogParser
	stackTraceParser *StackTraceParser
}

func NewMultiParser() *MultiParser {
	return &MultiParser{
		jsonParser:       NewJSONParser(),
		syslogParser:     NewSyslogParser(),
		stackTraceParser: NewStackTraceParser(),
	}
}

func (m *MultiParser) Parse(raw domain.RawEvent) (*domain.NormalizedEvent, error) {
	switch raw.Source {
	case domain.SourceJSON:
		return m.jsonParser.Parse(raw)
	case domain.SourceSyslog:
		return m.syslogParser.Parse(raw)
	case domain.SourceStackTrace:
		return m.stackTraceParser.Parse(raw)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnhandledSource, raw.Source)
	}
}

// JSONParser parses JSON-formatted log lines.
type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) Parse(raw domain.RawEvent) (*domain.NormalizedEvent, error) {
	if len(raw.Payload) == 0 {
		return nil, domain.ErrEmptyPayload
	}

	var rawMap map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw.Payload))
	decoder.UseNumber()
	if err := decoder.Decode(&rawMap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	ne := &domain.NormalizedEvent{
		Source:  domain.SourceJSON,
		RawSize: len(raw.Payload),
		Fields:  make(map[string]string),
	}

	var levelStr, msgStr, serviceStr, hostStr string
	var tsValue any
	var stackFrames []string

	for k, v := range rawMap {
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "service", "app", "app_name", "service_name":
			if s, ok := v.(string); ok {
				serviceStr = s
			}
		case "level", "severity", "log_level", "lvl":
			if s, ok := v.(string); ok {
				levelStr = s
			}
		case "msg", "message", "error", "err_msg":
			if s, ok := v.(string); ok {
				msgStr = s
			}
		case "host", "hostname", "server":
			if s, ok := v.(string); ok {
				hostStr = s
			}
		case "timestamp", "time", "ts", "@timestamp":
			tsValue = v
		case "stack", "stacktrace", "trace", "exception":
			switch val := v.(type) {
			case string:
				lines := strings.Split(val, "\n")
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" {
						stackFrames = append(stackFrames, trimmed)
					}
				}
			case []any:
				for _, elem := range val {
					if s, ok := elem.(string); ok && strings.TrimSpace(s) != "" {
						stackFrames = append(stackFrames, strings.TrimSpace(s))
					}
				}
			}
		default:
			ne.Fields[k] = fmt.Sprintf("%v", v)
		}
	}

	ne.Service = serviceStr
	ne.Host = hostStr
	ne.Message = msgStr
	ne.Severity = domain.ParseSeverity(strings.ToLower(levelStr))
	ne.StackFrames = stackFrames
	ne.Timestamp = parseJSONTimestamp(tsValue, raw.ReceivedAt)

	if ne.Service == "" {
		if raw.StreamID != "" {
			ne.Service = raw.StreamID
		} else {
			ne.Service = "unknown-service"
		}
	}

	return ne, nil
}

func parseJSONTimestamp(val any, fallback time.Time) time.Time {
	if val == nil {
		return fallback
	}

	switch v := val.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		if t, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
			return t
		}
	case json.Number:
		if i, err := v.Int64(); err == nil {
			if i > 1e11 {
				return time.UnixMilli(i).UTC()
			}
			return time.Unix(i, 0).UTC()
		}
		if f, err := v.Float64(); err == nil {
			sec := int64(f)
			nsec := int64((f - float64(sec)) * 1e9)
			return time.Unix(sec, nsec).UTC()
		}
	}

	return fallback
}

// SyslogParser parses RFC 3164 Syslog formatted lines: <PRI>TIMESTAMP HOST TAG[PID]: MESSAGE
type SyslogParser struct{}

func NewSyslogParser() *SyslogParser {
	return &SyslogParser{}
}

func (p *SyslogParser) Parse(raw domain.RawEvent) (*domain.NormalizedEvent, error) {
	if len(raw.Payload) == 0 {
		return nil, domain.ErrEmptyPayload
	}

	line := strings.TrimSpace(string(raw.Payload))
	ne := &domain.NormalizedEvent{
		Source:  domain.SourceSyslog,
		RawSize: len(raw.Payload),
		Fields:  make(map[string]string),
	}

	if !strings.HasPrefix(line, "<") {
		ne.Message = line
		ne.Severity = domain.SeverityInfo
		ne.Timestamp = raw.ReceivedAt
		ne.Service = fallbackService(raw.StreamID)
		return ne, nil
	}

	endPri := strings.IndexByte(line, '>')
	if endPri < 2 {
		ne.Message = line
		ne.Severity = domain.SeverityInfo
		ne.Timestamp = raw.ReceivedAt
		ne.Service = fallbackService(raw.StreamID)
		return ne, nil
	}

	priVal, err := strconv.Atoi(line[1:endPri])
	if err != nil {
		ne.Message = line
		ne.Severity = domain.SeverityInfo
		ne.Timestamp = raw.ReceivedAt
		ne.Service = fallbackService(raw.StreamID)
		return ne, nil
	}

	syslogSev := priVal % 8
	ne.Severity = mapSyslogSeverity(syslogSev)
	ne.Fields["syslog_facility"] = strconv.Itoa(priVal / 8)
	ne.Fields["syslog_pri"] = strconv.Itoa(priVal)

	rest := strings.TrimSpace(line[endPri+1:])

	parsedTime, remaining, ok := parseSyslogTimestamp(rest, raw.ReceivedAt)
	if ok {
		ne.Timestamp = parsedTime
		rest = remaining
	} else {
		ne.Timestamp = raw.ReceivedAt
	}

	colonIdx := strings.IndexByte(rest, ':')
	if colonIdx != -1 {
		header := rest[:colonIdx]
		ne.Message = strings.TrimSpace(rest[colonIdx+1:])

		headerParts := strings.Fields(header)
		if len(headerParts) >= 2 {
			ne.Host = headerParts[0]
			tagPart := headerParts[1]
			ne.Service, ne.Fields["pid"] = parseTagAndPID(tagPart)
		} else if len(headerParts) == 1 {
			ne.Service, ne.Fields["pid"] = parseTagAndPID(headerParts[0])
		}
	} else {
		ne.Message = rest
	}

	if ne.Service == "" {
		ne.Service = fallbackService(raw.StreamID)
	}

	return ne, nil
}

func mapSyslogSeverity(sev int) domain.Severity {
	switch sev {
	case 0, 1, 2:
		return domain.SeverityFatal
	case 3:
		return domain.SeverityError
	case 4:
		return domain.SeverityWarn
	case 5, 6:
		return domain.SeverityInfo
	case 7:
		return domain.SeverityDebug
	default:
		return domain.SeverityUnknown
	}
}

func parseSyslogTimestamp(s string, fallback time.Time) (time.Time, string, bool) {
	if len(s) < 15 {
		return fallback, s, false
	}

	tsStr := s[:15]
	currentYear := fallback.Year()
	if currentYear == 0 {
		currentYear = time.Now().Year()
	}

	t, err := time.ParseInLocation("Jan _2 15:04:05", tsStr, time.UTC)
	if err == nil {
		t = t.AddDate(currentYear, 0, 0)
		return t, strings.TrimSpace(s[15:]), true
	}

	return fallback, s, false
}

func parseTagAndPID(tag string) (service string, pid string) {
	if bracketIdx := strings.IndexByte(tag, '['); bracketIdx != -1 {
		service = tag[:bracketIdx]
		if endBracket := strings.IndexByte(tag[bracketIdx:], ']'); endBracket != -1 {
			pid = tag[bracketIdx+1 : bracketIdx+endBracket]
		}
		return service, pid
	}
	return tag, ""
}

// StackTraceParser parses multi-line stack trace payloads.
type StackTraceParser struct{}

func NewStackTraceParser() *StackTraceParser {
	return &StackTraceParser{}
}

func (p *StackTraceParser) Parse(raw domain.RawEvent) (*domain.NormalizedEvent, error) {
	if len(raw.Payload) == 0 {
		return nil, domain.ErrEmptyPayload
	}

	lines := strings.Split(string(raw.Payload), "\n")
	var cleanLines []string
	for _, l := range lines {
		trimmed := strings.TrimRight(l, "\r\n")
		if trimmed != "" {
			cleanLines = append(cleanLines, trimmed)
		}
	}

	if len(cleanLines) == 0 {
		return nil, ErrEmptyStackTrace
	}

	ne := &domain.NormalizedEvent{
		Source:    domain.SourceStackTrace,
		Timestamp: raw.ReceivedAt,
		RawSize:   len(raw.Payload),
		Fields:    make(map[string]string),
	}

	ne.Message = cleanLines[0]

	if len(cleanLines) > 1 {
		ne.StackFrames = cleanLines[1:]
	}

	lowerMsg := strings.ToLower(ne.Message)
	if strings.Contains(lowerMsg, "panic") || strings.Contains(lowerMsg, "fatal") || strings.Contains(lowerMsg, "critical") {
		ne.Severity = domain.SeverityFatal
	} else {
		ne.Severity = domain.SeverityError
	}

	ne.Service = fallbackService(raw.StreamID)

	return ne, nil
}

func fallbackService(streamID string) string {
	if streamID != "" {
		return streamID
	}
	return "app"
}
