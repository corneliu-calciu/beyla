//go:build linux

// Copyright Avesha Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t  -type flow_record_t -target amd64,arm64 NetSk ../../../../bpf/flows_sock.c -- -I../../../../bpf/headers

const (
	tcpLifeFlowsMap       = "tcplife_flows"
	tcpLifeFlowHistoryMap = "tcplife_flow_history"
)

// TCPLifeFlowFetcher reads and forwards the Flows from the eBPF kernel space with a socket filter implementation.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type TCPLifeFlowFetcher struct {
	objects       *NetSkObjects
	ringbufReader *ringbuf.Reader
	cacheMaxSize  int
	kp            link.Link
}

func NewTCPLifeFlowFetcher(
	sampling, cacheMaxSize int,
) (*TCPLifeFlowFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := NetSkObjects{}
	spec, err := LoadNetSk()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	tlog.Info(">>>>>>>>>>>>>>>>>>>>>> TCPLife fetcher <<<<<<<<<<<<<<<")

	// Resize aggregated flows and flow directions maps according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(1)
	spec.Maps[flowDirectionsMap].MaxEntries = uint32(1)
	spec.Maps[connInitiatorsMap].MaxEntries = uint32(1)

	spec.Maps[tcpLifeFlowsMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[tcpLifeFlowHistoryMap].MaxEntries = uint32(cacheMaxSize)

	traceMsgs := 0
	if tlog.Enabled(context.TODO(), slog.LevelDebug) {
		traceMsgs = 1
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling:      uint32(sampling),
		constTraceMessages: uint8(traceMsgs),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSize: 640 * 1024},
	}); err != nil {
		printVerifierErrorInfo(err)
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Insert TCPLife hook
	kp, err := link.Tracepoint("sock", "inet_sock_set_state", objects.HandleSetState, nil)
	if err != nil {
		tlog.Error("TCPLife: Tracepoint failed", "error", err)
		return nil, fmt.Errorf("opening kprobe: %s", err)
	} else {
		tlog.Info("TCPLife: Successfully installed hook")
	}

	// read events from socket filter ringbuffer
	// TODO: add support for ringbuffer notifications later
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &TCPLifeFlowFetcher{
		objects:       &objects,
		ringbufReader: flows,
		cacheMaxSize:  cacheMaxSize,
		kp:            kp,
	}, nil
}

// Noop because socket filters don't require special registration for different network interfaces
func (m *TCPLifeFlowFetcher) Register(_ ifaces.Interface) error {
	return nil
}

// Close any resources that are taken up by the socket filter, the filter itself and some maps.
func (m *TCPLifeFlowFetcher) Close() error {
	log := tlog()
	log.Debug("unregistering eBPF objects")

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objects != nil {
		errs = append(errs, m.closeObjects()...)
	}
	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *TCPLifeFlowFetcher) closeObjects() []error {
	var errs []error
	if err := m.objects.SocketHttpFilter.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.AggregatedFlows.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.DirectFlows.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.HandleSetState.Close(); err != nil {
		errs = append(errs, err)
	}
	m.objects = nil
	return errs
}

func (m *TCPLifeFlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
func (m *TCPLifeFlowFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
	tlog().Debug("LookupAndDeleteMapTCPLife ...")

	flowMap := m.objects.TcplifeFlows

	iterator := flowMap.Iterate()
	flows := make(map[NetFlowId][]NetFlowMetrics, m.cacheMaxSize)

	id := NetFlowId{}
	var metrics []NetFlowMetrics
	count := 0
	for iterator.Next(&id, &metrics) {
		if err := flowMap.Delete(id); err != nil {
			tlog().Warn("couldn't delete flow entry", "flowId", id)
		}
		for i := 0; i < len(metrics); i++ {
			// Skip empty records
			if metrics[i].Bytes == 0 && metrics[i].Txbytes == 0 {
				continue
			}
			data := fmt.Sprintf("%v DIP:%v", metrics[i], id.DstIp)
			tlog().Debug("LookupAndDeleteMapTCPLife", "state", metrics[i].State, "metrics", data)
			flows[id] = append(flows[id], metrics[i])
		}
		count += 1
		data := fmt.Sprintf("%v", id)
		tlog().Debug("LookupAndDeleteMapTCPLife", "data", data)
	}

	tlog().Debug("LookupAndDeleteMapTCPLife", "count", count)
	return flows
}
