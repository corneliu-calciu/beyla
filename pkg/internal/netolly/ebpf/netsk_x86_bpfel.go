// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type NetSkConnInitiatorKey struct {
	LowIp      struct{ In6U struct{ U6Addr8 [16]uint8 } }
	HighIp     struct{ In6U struct{ U6Addr8 [16]uint8 } }
	LowIpPort  uint16
	HighIpPort uint16
}

type NetSkFlowId NetSkFlowIdT

type NetSkFlowIdT struct {
	SrcIp             struct{ In6U struct{ U6Addr8 [16]uint8 } }
	DstIp             struct{ In6U struct{ U6Addr8 [16]uint8 } }
	EthProtocol       uint16
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	IfIndex           uint32
}

type NetSkFlowMetrics NetSkFlowMetricsT

type NetSkFlowMetricsT struct {
	Packets         uint32
	Bytes           uint64
	StartMonoTimeNs uint64
	EndMonoTimeNs   uint64
	Flags           uint16
	IfaceDirection  uint8
	Initiator       uint8
	Errno           uint8
	State           uint8
	Rxbytes         uint64
	Txbytes         uint64
	Duration        uint64
}

type NetSkFlowRecordT struct {
	Id      NetSkFlowId
	Metrics NetSkFlowMetrics
}

// LoadNetSk returns the embedded CollectionSpec for NetSk.
func LoadNetSk() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_NetSkBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load NetSk: %w", err)
	}

	return spec, err
}

// LoadNetSkObjects loads NetSk and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*NetSkObjects
//	*NetSkPrograms
//	*NetSkMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadNetSkObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadNetSk()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// NetSkSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type NetSkSpecs struct {
	NetSkProgramSpecs
	NetSkMapSpecs
}

// NetSkSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type NetSkProgramSpecs struct {
	HandleSetState   *ebpf.ProgramSpec `ebpf:"handle_set_state"`
	SocketHttpFilter *ebpf.ProgramSpec `ebpf:"socket__http_filter"`
}

// NetSkMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type NetSkMapSpecs struct {
	AggregatedFlows    *ebpf.MapSpec `ebpf:"aggregated_flows"`
	ConnInitiators     *ebpf.MapSpec `ebpf:"conn_initiators"`
	DirectFlows        *ebpf.MapSpec `ebpf:"direct_flows"`
	FlowDirections     *ebpf.MapSpec `ebpf:"flow_directions"`
	TcplifeFlowHistory *ebpf.MapSpec `ebpf:"tcplife_flow_history"`
	TcplifeFlows       *ebpf.MapSpec `ebpf:"tcplife_flows"`
}

// NetSkObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadNetSkObjects or ebpf.CollectionSpec.LoadAndAssign.
type NetSkObjects struct {
	NetSkPrograms
	NetSkMaps
}

func (o *NetSkObjects) Close() error {
	return _NetSkClose(
		&o.NetSkPrograms,
		&o.NetSkMaps,
	)
}

// NetSkMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadNetSkObjects or ebpf.CollectionSpec.LoadAndAssign.
type NetSkMaps struct {
	AggregatedFlows    *ebpf.Map `ebpf:"aggregated_flows"`
	ConnInitiators     *ebpf.Map `ebpf:"conn_initiators"`
	DirectFlows        *ebpf.Map `ebpf:"direct_flows"`
	FlowDirections     *ebpf.Map `ebpf:"flow_directions"`
	TcplifeFlowHistory *ebpf.Map `ebpf:"tcplife_flow_history"`
	TcplifeFlows       *ebpf.Map `ebpf:"tcplife_flows"`
}

func (m *NetSkMaps) Close() error {
	return _NetSkClose(
		m.AggregatedFlows,
		m.ConnInitiators,
		m.DirectFlows,
		m.FlowDirections,
		m.TcplifeFlowHistory,
		m.TcplifeFlows,
	)
}

// NetSkPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadNetSkObjects or ebpf.CollectionSpec.LoadAndAssign.
type NetSkPrograms struct {
	HandleSetState   *ebpf.Program `ebpf:"handle_set_state"`
	SocketHttpFilter *ebpf.Program `ebpf:"socket__http_filter"`
}

func (p *NetSkPrograms) Close() error {
	return _NetSkClose(
		p.HandleSetState,
		p.SocketHttpFilter,
	)
}

func _NetSkClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed netsk_x86_bpfel.o
var _NetSkBytes []byte
