package attributes

import (
	"maps"

	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
)

// AttrGroups will let enabling by default some groups of attributes under
// given circumstances. For example, will let enabling kubernetes metadata attributes
// only if Beyla is running under Kubernetes and kube metadata is enabled.
type AttrGroups int

const (
	UndefinedGroup  = AttrGroups(0)
	GroupKubernetes = AttrGroups(1 << iota)
	GroupPrometheus
	GroupHTTPRoutes
	GroupNetIfaceDirection
	GroupNetCIDR
	GroupTraces
	GroupApp
	GroupNet
	GroupNetKube
	GroupAppKube
	GroupServerInfo
	GroupHTTPClientInfo
	GroupGRPCClientInfo
	GroupHTTPCommon
	GroupHost
	GroupPromProcess
	GroupProcess
	GroupMessaging
)

func (e *AttrGroups) Has(groups AttrGroups) bool {
	return *e&groups != 0
}

func (e *AttrGroups) Add(groups AttrGroups) {
	*e |= groups
}

// Any new metric and attribute must be added here to be matched from the user-provided wildcard
// selectors of the attributes.select section
func getDefinitions(
	groups AttrGroups,
	extraGroupAttributes GroupAttributes,
) map[Section]AttrReportGroup {
	kubeEnabled := groups.Has(GroupKubernetes)
	promEnabled := groups.Has(GroupPrometheus)
	ifaceDirEnabled := groups.Has(GroupNetIfaceDirection)
	cidrEnabled := groups.Has(GroupNetCIDR)

	// attributes to be reported exclusively for prometheus exporters
	prometheusAttributes := newAttrReportGroup(
		!promEnabled,
		nil,
		map[attr.Name]Default{
			attr.Instance:         true,
			attr.Job:              true,
			attr.ServiceNamespace: true,
		},
		extraGroupAttributes[GroupPrometheus],
	)

	// ServiceName and ServiceNamespace are reported both as resource and metric attributes, as
	// the OTEL definition requires that it is reported as resource attribute,
	// but Grafana Cloud takes it from the metric
	appAttributes := newAttrReportGroup(
		false,
		[]*AttrReportGroup{&prometheusAttributes},
		map[attr.Name]Default{
			attr.ServiceName:      true,
			attr.ServiceNamespace: true,
		},
		extraGroupAttributes[GroupApp],
	)

	// network metrics attributes
	networkAttributes := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]Default{
			attr.Direction:      true,
			attr.BeylaIP:        false,
			attr.Transport:      false,
			attr.SrcAddress:     false,
			attr.DstAddres:      false,
			attr.SrcPort:        false,
			attr.DstPort:        false,
			attr.SrcName:        false,
			attr.DstName:        false,
			attr.ServerPort:     false,
			attr.ClientPort:     false,
			attr.SrcZone:        false,
			attr.DstZone:        false,
			attr.IfaceDirection: Default(ifaceDirEnabled),
			attr.Iface:          Default(ifaceDirEnabled),
		},
		extraGroupAttributes[GroupNet],
	)

	// attributes to be reported exclusively for network metrics when
	// kubernetes metadata is enabled
	networkKubeAttributes := newAttrReportGroup(
		!kubeEnabled,
		nil,
		map[attr.Name]Default{
			attr.K8sSrcOwnerName: true,
			attr.K8sSrcOwnerType: true,
			attr.K8sSrcNamespace: true,
			attr.K8sDstOwnerName: true,
			attr.K8sDstOwnerType: true,
			attr.K8sDstNamespace: true,
			attr.K8sClusterName:  true,
			attr.K8sSrcName:      false,
			attr.K8sSrcType:      false,
			attr.K8sSrcNodeIP:    false,
			attr.K8sSrcNodeName:  false,
			attr.K8sDstName:      false,
			attr.K8sDstType:      false,
			attr.K8sDstNodeIP:    false,
			attr.K8sDstNodeName:  false,
		},
		extraGroupAttributes[GroupNetKube],
	)

	// network CIDR attributes are only enabled if the CIDRs configuration
	// is defined
	networkCIDR := newAttrReportGroup(
		!cidrEnabled,
		nil,
		map[attr.Name]Default{
			attr.DstCIDR: true,
			attr.SrcCIDR: true,
		},
		extraGroupAttributes[GroupNetCIDR],
	)

	// networkInterZone* supports the same attributes as
	// network* counterpart, but all of them disabled by default, to keep cardinality low
	networkInterZone := copyDisabled(networkAttributes)
	networkInterZone.Attributes[attr.K8sClusterName] = true
	networkInterZoneKube := copyDisabled(networkKubeAttributes)
	networkInterZoneCIDR := copyDisabled(networkCIDR)
	// only src and dst zone are enabled by default
	networkInterZone.Attributes[attr.SrcZone] = true
	networkInterZone.Attributes[attr.DstZone] = true

	// attributes to be reported exclusively for application metrics when
	// kubernetes metadata is enabled
	appKubeAttributes := newAttrReportGroup(
		!kubeEnabled,
		nil,
		map[attr.Name]Default{
			attr.K8sNamespaceName:   true,
			attr.K8sPodName:         true,
			attr.K8sContainerName:   true,
			attr.K8sDeploymentName:  true,
			attr.K8sReplicaSetName:  true,
			attr.K8sDaemonSetName:   true,
			attr.K8sStatefulSetName: true,
			attr.K8sNodeName:        true,
			attr.K8sPodUID:          true,
			attr.K8sPodStartTime:    true,
			attr.K8sClusterName:     true,
			attr.K8sOwnerName:       true,
			attr.K8sKind:            true,
		},
		extraGroupAttributes[GroupAppKube],
	)

	httpRoutes := newAttrReportGroup(
		!groups.Has(GroupHTTPRoutes),
		nil,
		map[attr.Name]Default{
			attr.HTTPRoute: true,
		},
		extraGroupAttributes[GroupHTTPRoutes],
	)

	serverInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]Default{
			attr.ClientAddr: false,
			attr.ServerAddr: true,
			attr.ServerPort: true,
		},
		extraGroupAttributes[GroupServerInfo],
	)

	httpClientInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]Default{
			attr.ServerAddr: true,
			attr.ServerPort: true,
		},
		extraGroupAttributes[GroupHTTPClientInfo],
	)

	grpcClientInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]Default{
			attr.ServerAddr: true,
		},
		extraGroupAttributes[GroupGRPCClientInfo],
	)

	httpCommon := newAttrReportGroup(
		false,
		[]*AttrReportGroup{&httpRoutes},
		map[attr.Name]Default{
			attr.HTTPRequestMethod:      true,
			attr.HTTPResponseStatusCode: true,
			attr.HTTPUrlPath:            false,
		},
		extraGroupAttributes[GroupHTTPCommon],
	)

	// TODO: populate it with host resource attributes in https://opentelemetry.io/docs/specs/semconv/resource/host/
	hostAttributes := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]Default{
			attr.HostName: true,
		},
		extraGroupAttributes[GroupHost],
	)

	// the following attributes are only reported as metric attributes in Prometheus,
	// as the OTEL standard defines them as resource attributes.
	promProcessAttributes := newAttrReportGroup(
		!promEnabled,
		nil,
		map[attr.Name]Default{
			attr.Instance:        true,
			attr.Job:             true,
			attr.ProcCommand:     true,
			attr.ProcOwner:       true,
			attr.ProcParentPid:   true,
			attr.ProcPid:         true,
			attr.ProcCommandLine: false,
			attr.ProcCommandArgs: false,
			attr.ProcExecName:    false,
			attr.ProcExecPath:    false,
		},
		extraGroupAttributes[GroupPromProcess],
	)

	processAttributes := newAttrReportGroup(
		false,
		[]*AttrReportGroup{&appKubeAttributes, &hostAttributes, &promProcessAttributes},
		map[attr.Name]Default{
			attr.ProcCPUMode:   true,
			attr.ProcDiskIODir: true,
			attr.ProcNetIODir:  true,
		},
		extraGroupAttributes[GroupProcess],
	)

	messagingAttributes := newAttrReportGroup(
		false,
		[]*AttrReportGroup{&appAttributes, &appKubeAttributes},
		map[attr.Name]Default{
			attr.MessagingSystem:      true,
			attr.MessagingDestination: true,
		},
		extraGroupAttributes[GroupMessaging],
	)

	return map[Section]AttrReportGroup{
		BeylaNetworkFlow.Section: {
			SubGroups: []*AttrReportGroup{&networkAttributes, &networkCIDR, &networkKubeAttributes},
		},
		BeylaNetworkInterZone.Section: {
			SubGroups: []*AttrReportGroup{&networkInterZone, &networkInterZoneCIDR, &networkInterZoneKube},
		},
		HTTPServerDuration.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPServerRequestSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPServerResponseSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPClientDuration.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		HTTPClientRequestSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		HTTPClientResponseSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		RPCClientDuration.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &grpcClientInfo},
			Attributes: map[attr.Name]Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
			},
		},
		RPCServerDuration.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes, &serverInfo},
			Attributes: map[attr.Name]Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
			},
		},
		DBClientDuration.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{
				attr.DBOperation:  true,
				attr.DBSystemName: true,
				attr.ErrorType:    true,
			},
		},
		MessagingPublishDuration.Section: {
			SubGroups: []*AttrReportGroup{&messagingAttributes},
		},
		MessagingProcessDuration.Section: {
			SubGroups: []*AttrReportGroup{&messagingAttributes},
		},
		Traces.Section: {
			Attributes: map[attr.Name]Default{
				attr.DBQueryText: false,
			},
		},
		ProcessCPUUtilization.Section: {SubGroups: []*AttrReportGroup{&processAttributes}},
		ProcessCPUTime.Section:        {SubGroups: []*AttrReportGroup{&processAttributes}},
		ProcessMemoryUsage.Section:    {SubGroups: []*AttrReportGroup{&processAttributes}},
		ProcessMemoryVirtual.Section:  {SubGroups: []*AttrReportGroup{&processAttributes}},
		ProcessDiskIO.Section:         {SubGroups: []*AttrReportGroup{&processAttributes}},
		ProcessNetIO.Section:          {SubGroups: []*AttrReportGroup{&processAttributes}},
		GPUKernelLaunchCalls.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{
				attr.CudaKernelName: true,
			},
		},
		GPUKernelGridSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{
				attr.CudaKernelName: true,
			},
		},
		GPUKernelBlockSize.Section: {
			SubGroups: []*AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{
				attr.CudaKernelName: true,
			},
		},
		GPUMemoryAllocations.Section: {
			SubGroups:  []*AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{},
		},
		// span and service graph metrics don't yet implement attribute selection,
		// but their values can still be filtered, so we list them here just to
		// make the filter recognize its attributes
		// TODO: when service graph and spam metrics implement attribute selection, replace this section by proper metric names
		"---- temporary placeholder for span and service graph metrics ----": {
			Attributes: map[attr.Name]Default{
				attr.Client:            false,
				attr.ClientNamespace:   false,
				attr.Server:            false,
				attr.ServerNamespace:   false,
				attr.Source:            false,
				attr.ServiceName:       false,
				attr.ServiceInstanceID: false,
				attr.ServiceNamespace:  false,
				attr.SpanKind:          false,
				attr.SpanName:          false,
				attr.StatusCode:        false,
			},
		},
	}
}

func copyDisabled(src AttrReportGroup) AttrReportGroup {
	var dst = AttrReportGroup{
		Disabled:   src.Disabled,
		Attributes: map[attr.Name]Default{},
	}
	for k := range src.Attributes {
		dst.Attributes[k] = false
	}
	return dst
}

// AllAttributeNames returns a set with all the names in the attributes database
// as returned by the getDefinitions function
func AllAttributeNames(extraGroupAttributesCfg map[string][]attr.Name) map[attr.Name]struct{} {
	extraGroupAttributes := newGroupAttributes(extraGroupAttributesCfg)
	names := map[attr.Name]struct{}{}
	// -1 to enable all the metric group flags
	for _, section := range getDefinitions(-1, extraGroupAttributes) {
		maps.Copy(names, section.All())
	}
	return names
}
