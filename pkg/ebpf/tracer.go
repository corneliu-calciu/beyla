package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/grpc"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

// Tracer is an individual eBPF program (e.g. the net/http or the grpc tracers)
type Tracer interface {
	// Load the bpf object that is generated by the bpf2go compiler
	Load() (*ebpf.CollectionSpec, error)
	// Constants returns a map of constants to be overriden into the eBPF program.
	// The key is the constant name and the value is the value to overwrite.
	Constants(*goexec.Offsets) map[string]any
	// BpfObjects that are created by the bpf2go compiler
	BpfObjects() any
	// Probes returns a map with the name of the functions that need to be inspected
	// in the executable, as well as the eBPF programs that optionally need to be
	// inserted as the function start and end probes
	Probes() map[string]ebpfcommon.FunctionPrograms
	// Run will do the action of listening for eBPF traces and forward them
	// periodically to the output channel.
	Run(context.Context, chan<- []ebpfcommon.HTTPRequestTrace)
	// AddCloser adds io.Closer instances that need to be invoked when the
	// Run function ends.
	AddCloser(c ...io.Closer)
}

// TracerProvider returns a StartFuncCtx for each discovered eBPF traceable source: GRPC, HTTP...
func TracerProvider(cfg ebpfcommon.TracerConfig) []node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace] { //nolint:all
	log := slog.With("component", "ebpf.TracerProvider")

	// Each program is an eBPF source: net/http, grpc...
	programs := []Tracer{
		&nethttp.Tracer{Cfg: &cfg},
		&nethttp.GinTracer{Tracer: nethttp.Tracer{Cfg: &cfg}},
		&grpc.Tracer{Cfg: &cfg},
	}

	// merging all the functions from all the programs, in order to do
	// a complete inspection of the target executable
	allFuncs := allFunctionNames(programs)
	offsets, err := inspect(&cfg, allFuncs)
	if err != nil {
		log.Error("inspecting offsets", err)
		// TODO: rework pipes API to allow returning the errors to the pipe builder
		return nil
	}

	programs = filterNotFoundPrograms(programs, offsets)
	if len(programs) == 0 {
		log.Error("the executable is not instrumentable. Exiting", fmt.Errorf("no instrumentable function found"))
		return nil
	}

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(offsets.FileInfo.ProExeLinkPath)
	if err != nil {
		log.Error("opening executable file. Exiting", err, "path", offsets.FileInfo.ProExeLinkPath)
		return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("removing memory lock. Exiting", err)
		return nil
	}

	var runFunctions []node.StartFuncCtx[[]ebpfcommon.HTTPRequestTrace]
	for _, p := range programs {
		plog := log.With("program", reflect.TypeOf(p))
		plog.Debug("loading eBPF program")
		spec, err := p.Load()
		if err != nil {
			plog.Error("loading eBPF program", err)
			return nil
		}
		if err := spec.RewriteConstants(p.Constants(offsets)); err != nil {
			plog.Error("rewriting BPF constants definition", err)
			return nil
		}
		if err := spec.LoadAndAssign(p.BpfObjects(), nil); err != nil {
			plog.Error("loading and assigning BPF objects", err)
			printVerifierErrorInfo(err)
			return nil
		}
		i := instrumenter{
			exe:     exe,
			offsets: offsets,
		}
		// TODO: not running program if it does not find the required probes
		for funcName, funcPrograms := range p.Probes() {
			offs, ok := offsets.Funcs[funcName]
			if !ok {
				// the program function is not in the detected offsets. Ignoring
				continue
			}
			slog.Debug("going to instrument function", "function", funcName, "offsets", offs, "programs", funcPrograms)
			if err := i.instrument(ebpfcommon.Probe{
				Offsets:  offs,
				Programs: funcPrograms,
			}); err != nil {
				plog.Error("instrumenting function", err, "function", funcName)
				printVerifierErrorInfo(err)
				return nil
			}
			p.AddCloser(i.uprobes...)
		}
		runFunctions = append(runFunctions, p.Run)
	}

	return runFunctions
}

// filterNotFoundPrograms will filter these programs whose required functions (as
// returned in the Offsets method) haven't been found in the offsets
func filterNotFoundPrograms(programs []Tracer, offsets *goexec.Offsets) []Tracer {
	var filtered []Tracer
	funcs := offsets.Funcs
programs:
	for _, p := range programs {
		for fn, fp := range p.Probes() {
			if !fp.Required {
				continue
			}
			if _, ok := funcs[fn]; !ok {
				continue programs
			}
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func allFunctionNames(programs []Tracer) []string {
	uniqueFunctions := map[string]struct{}{}
	var functions []string
	for _, p := range programs {
		for funcName := range p.Probes() {
			// avoid duplicating function names
			if _, ok := uniqueFunctions[funcName]; !ok {
				uniqueFunctions[funcName] = struct{}{}
				functions = append(functions, funcName)
			}
		}
	}
	return functions
}

func inspect(cfg *ebpfcommon.TracerConfig, functions []string) (*goexec.Offsets, error) {
	var finder goexec.ProcessFinder
	if cfg.Port != 0 {
		finder = goexec.OwnedPort(cfg.Port)
	} else {
		finder = goexec.ProcessNamed(cfg.Exec)
	}
	offsets, err := goexec.InspectOffsets(finder, functions)
	if err != nil {
		return nil, fmt.Errorf("error analysing target executable: %w", err)
	}
	if cfg.OnOffsets != nil {
		cfg.OnOffsets(offsets)
	}
	return offsets, nil
}

type instrumenter struct {
	offsets *goexec.Offsets
	exe     *link.Executable
	uprobes []io.Closer
}

func (i *instrumenter) instrument(probe ebpfcommon.Probe) error {
	// Attach BPF programs as start and return probes
	if probe.Programs.Start != nil {
		up, err := i.exe.Uprobe("", probe.Programs.Start, &link.UprobeOptions{
			Address: probe.Offsets.Start,
		})
		if err != nil {
			return fmt.Errorf("setting uprobe: %w", err)
		}
		i.uprobes = append(i.uprobes, up)
	}

	if probe.Programs.End != nil {
		// Go won't work with Uretprobes because of the way Go manages the stack. We need to set uprobes just before the return
		// values: https://github.com/iovisor/bcc/issues/1320
		for _, ret := range probe.Offsets.Returns {
			urp, err := i.exe.Uprobe("", probe.Programs.End, &link.UprobeOptions{
				Address: ret,
			})
			if err != nil {
				return fmt.Errorf("setting uretprobe: %w", err)
			}
			i.uprobes = append(i.uprobes, urp)
		}
	}

	return nil
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}
