package alloy

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(ctx context.Context, cfg *beyla.TracesReceiverConfig, userAttribSelection attributes.Selection) pipe.FinalProvider[[]request.Span] {
	return (&tracesReceiver{ctx: ctx, cfg: cfg, attributes: userAttribSelection}).provideLoop
}

type tracesReceiver struct {
	ctx        context.Context
	cfg        *beyla.TracesReceiverConfig
	attributes attributes.Selection
}

func (tr *tracesReceiver) provideLoop() (pipe.FinalFunc[[]request.Span], error) {
	if !tr.cfg.Enabled() {
		return pipe.IgnoreFinal[[]request.Span](), nil
	}
	return func(in <-chan []request.Span) {
		// Get user attributes
		traceAttrs, err := otel.GetUserSelectedAttributes(tr.attributes)
		if err != nil {
			slog.Error("error fetching user defined attributes", "error", err)
		}

		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}

				for _, tc := range tr.cfg.Traces {
					traces := otel.GenerateTraces(span, traceAttrs)
					err := tc.ConsumeTraces(tr.ctx, traces)
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}
