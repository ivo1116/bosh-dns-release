package internal

import (
	"fmt"
	"strings"

	"github.com/cloudfoundry/bosh-utils/logger"
	"github.com/miekg/dns"
)

// queryLoggingEnabled gates the opt-in query log set via SetQueryLogging.
var queryLoggingEnabled bool

func SetQueryLogging(enabled bool) {
	queryLoggingEnabled = enabled
}

func ClientAddr(rw dns.ResponseWriter) string {
	if rw == nil {
		return ""
	}
	if addr := rw.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func LogRequest(logger logger.Logger, handler dns.Handler, logTag string, duration int64, request *dns.Msg, response *dns.Msg, customMessage string, clientAddr string) {
	types, domains := readQuestions(request)

	if customMessage != "" {
		customMessage = customMessage + " "
	}

	rcode := dns.RcodeServerFailure
	numAnswers := 0
	if response != nil {
		rcode = response.Rcode
		numAnswers = len(response.Answer)
	}

	clientFragment := ""
	if clientAddr != "" {
		clientFragment = fmt.Sprintf("client=[%s] ", clientAddr)
	}

	logLine := fmt.Sprintf("%T Request id=%d qtype=[%s] qname=[%s] rcode=%s ancount=%d %s%stime=%dns",
		handler,
		request.Id,
		strings.Join(types, ","),
		strings.Join(domains, ","),
		dns.RcodeToString[rcode],
		numAnswers,
		clientFragment,
		customMessage,
		duration,
	)

	logger.Debug(logTag, logLine)

	if queryLoggingEnabled && clientAddr != "" {
		logger.Info(logTag, "dns-query client=[%s] qname=[%s] qtype=[%s] rcode=%s",
			clientAddr,
			strings.Join(domains, ","),
			strings.Join(types, ","),
			dns.RcodeToString[rcode],
		)
	}
}

func LogReceivedRequest(logger logger.Logger, handler dns.Handler, logTag string, request *dns.Msg) {
	types, domains := readQuestions(request)
	logLine := fmt.Sprintf("%T Received request id=%d qtype=[%s] qname=[%s]",
		handler,
		request.Id,
		strings.Join(types, ","),
		strings.Join(domains, ","),
	)

	logger.Debug(logTag, logLine)
}

func readQuestions(request *dns.Msg) ([]string, []string) {
	types := make([]string, len(request.Question))
	domains := make([]string, len(request.Question))

	for i, q := range request.Question {
		types[i] = dns.Type(q.Qtype).String()
		domains[i] = q.Name
	}
	return types, domains
}
