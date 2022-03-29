package controller

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// MasterController is the master hybrid overlay controller
type MasterController struct {
	kube             kube.Interface
	allocator        *subnetallocator.SubnetAllocator
	nodeEventHandler informer.EventHandler
	modelClient      libovsdbops.ModelClient
	nbClient         libovsdbclient.Client
	sbClient         libovsdbclient.Client
}

// NewMaster a new master controller that listens for node events
func NewMaster(kube kube.Interface,
	nodeInformer cache.SharedIndexInformer,
	namespaceInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
	libovsdbNBClient libovsdbclient.Client,
	libovsdbSBClient libovsdbclient.Client,
	eventHandlerCreateFunction informer.EventHandlerCreateFunction,
) (*MasterController, error) {

	modelClient := libovsdbops.NewModelClient(libovsdbNBClient)

	m := &MasterController{
		kube:        kube,
		allocator:   subnetallocator.NewSubnetAllocator(),
		modelClient: modelClient,
		nbClient:    libovsdbNBClient,
		sbClient:    libovsdbSBClient,
	}

	m.nodeEventHandler = eventHandlerCreateFunction("node", nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return m.AddNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return m.DeleteNode(node)
		},
		informer.ReceiveAllUpdates,
	)

	// Add our hybrid overlay CIDRs to the subnetallocator
	for _, clusterEntry := range config.HybridOverlay.ClusterSubnets {
		err := m.allocator.AddNetworkRange(clusterEntry.CIDR, clusterEntry.HostSubnetLength)
		if err != nil {
			return nil, err
		}
	}

	// Mark existing hostsubnets as already allocated
	existingNodes, err := m.kube.GetNodes()
	if err != nil {
		return nil, fmt.Errorf("error in initializing/fetching subnets: %v", err)
	}
	for _, node := range existingNodes.Items {
		hostsubnet, err := houtil.ParseHybridOverlayHostSubnet(&node)
		if err != nil {
			klog.Warningf(err.Error())
		} else if hostsubnet != nil {
			klog.V(5).Infof("Marking existing node %s hybrid overlay NodeSubnet %s as allocated", node.Name, hostsubnet)
			if err := m.allocator.MarkAllocatedNetwork(hostsubnet); err != nil {
				utilruntime.HandleError(err)
			}
		}
	}

	return m, nil
}

// Run starts the controller
func (m *MasterController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	klog.Info("Starting Hybrid Overlay Master Controller")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := m.nodeEventHandler.Run(informer.DefaultNodeInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	<-stopCh
	klog.Info("Shutting down Hybrid Overlay Master workers")
	wg.Wait()
	klog.Info("Shut down Hybrid Overlay Master workers")
}

// hybridOverlayNodeEnsureSubnet allocates a subnet and sets the
// hybrid overlay subnet annotation. It returns any newly allocated subnet
// or an error. If an error occurs, the newly allocated subnet will be released.
func (m *MasterController) hybridOverlayNodeEnsureSubnet(node *kapi.Node, annotator kube.Annotator) (*net.IPNet, error) {
	// Do not allocate a subnet if the node already has one
	if subnet, _ := houtil.ParseHybridOverlayHostSubnet(node); subnet != nil {
		return nil, nil
	}

	// Allocate a new host subnet for this node
	hostsubnets, err := m.allocator.AllocateNetworks()
	if err != nil {
		return nil, fmt.Errorf("error allocating hybrid overlay HostSubnet for node %s: %v", node.Name, err)
	}

	if err := annotator.Set(types.HybridOverlayNodeSubnet, hostsubnets[0].String()); err != nil {
		_ = m.allocator.ReleaseNetwork(hostsubnets[0])
		return nil, err
	}

	klog.Infof("Allocated hybrid overlay HostSubnet %s for node %s", hostsubnets[0], node.Name)
	return hostsubnets[0], nil
}

func (m *MasterController) releaseNodeSubnet(nodeName string, subnet *net.IPNet) error {
	if err := m.allocator.ReleaseNetwork(subnet); err != nil {
		return fmt.Errorf("error deleting hybrid overlay HostSubnet %s for node %q: %s", subnet, nodeName, err)
	}
	klog.Infof("Deleted hybrid overlay HostSubnet %s for node %s", subnet, nodeName)
	return nil
}

// handleOverlayPort reconciles the node's overlay port with OVN.
// It needs to handle the following cases:
//   - no subnet allocated: unset MAC annotation
//   - no MAC annotation, no lsp: configure lsp, set annotation
//   - annotation, no lsp: configure lsp
//   - annotation, lsp: ensure lsp matches annotation
//   - no annotation, lsp: set annotation from lsp
func (m *MasterController) handleOverlayPort(node *kapi.Node, annotator kube.Annotator) error {
	var err error
	var annotationMAC, portMAC net.HardwareAddr
	portName := util.GetHybridOverlayPortName(node.Name)

	// retrieve mac annotation
	am, annotationOK := node.Annotations[types.HybridOverlayDRMAC]
	if annotationOK {
		annotationMAC, err = net.ParseMAC(am)
		if err != nil {
			klog.Errorf("MAC annotation %s on node %s is invalid, ignoring.", annotationMAC, node.Name)
			annotationOK = false
		}
	}

	// no subnet allocated? unset mac annotation, be done.
	subnets, err := util.ParseNodeHostSubnetAnnotation(node)
	if subnets == nil || err != nil {
		// No subnet allocated yet; clean up
		klog.V(5).Infof("No subnet allocation yet for %s", node.Name)
		if annotationOK {
			m.deleteOverlayPort(node)
			annotator.Delete(types.HybridOverlayDRMAC)
		}
		return nil
	}

	// retrieve port configuration. If port isn't set up, portMAC will be nil
	portMAC, _, _ = util.GetPortAddresses(portName, m.nbClient)

	// compare port configuration to annotation MAC, reconcile as needed
	lspOK := false

	// nothing allocated, allocate default mac
	if portMAC == nil && annotationMAC == nil {
		for _, subnet := range subnets {
			ip := util.GetNodeHybridOverlayIfAddr(subnet).IP
			portMAC = util.IPAddrToHWAddr(ip)
			annotationMAC = portMAC
			if !utilnet.IsIPv6(ip) {
				break
			}
		}
		klog.V(5).Infof("Allocating MAC %s to node %s", portMAC.String(), node.Name)
	} else if portMAC == nil && annotationMAC != nil { // annotation, no port
		portMAC = annotationMAC
	} else if portMAC != nil && annotationMAC == nil { // port, no annotation
		lspOK = true
		annotationMAC = portMAC
	} else if portMAC != nil && annotationMAC != nil { // port & annotation: anno wins
		if portMAC.String() != annotationMAC.String() {
			klog.V(2).Infof("Warning: node %s lsp %s has mismatching hybrid port mac, correcting", node.Name, portName)
			portMAC = annotationMAC
		} else {
			lspOK = true
		}
	}

	// we need to setup a reroute policy for hybrid overlay subnet
	// this is so hybrid pod -> service -> hybrid endpoint will reroute to the DR IP
	if len(config.HybridOverlay.ClusterSubnets) > 0 {
		if err := m.setupHybridLRPolicySharedGw(subnets, node.Name, portMAC); err != nil {
			return fmt.Errorf("unable to setup Hybrid Subnet Logical Route Policy for node: %s, error: %v",
				node.Name, err)
		}
	}

	if !lspOK {
		klog.Infof("Creating / updating node %s hybrid overlay port with mac %s", node.Name, portMAC.String())

		// create / update lsps
		err := libovsdbops.CreateLSPOrMutateMac(m.nbClient, node.Name, portName, portMAC.String())
		if err != nil {
			return fmt.Errorf("failed to add hybrid overlay port for node %s"+
				", err: %v", node.Name, err)
		}
		for _, subnet := range subnets {
			if err := util.UpdateNodeSwitchExcludeIPs(m.nbClient, node.Name, subnet); err != nil {
				return err
			}
		}
	}

	if !annotationOK {
		klog.Infof("Setting node %s hybrid overlay mac annotation to %s", node.Name, annotationMAC.String())
		if err := annotator.Set(types.HybridOverlayDRMAC, portMAC.String()); err != nil {
			return fmt.Errorf("failed to set node %s hybrid overlay DRMAC annotation: %v", node.Name, err)
		}
	}

	return nil
}

func (m *MasterController) deleteOverlayPort(node *kapi.Node) {
	klog.Infof("Removing node %s hybrid overlay port", node.Name)
	portName := util.GetHybridOverlayPortName(node.Name)
	if err := libovsdbops.LSPDelete(m.nbClient, portName); err != nil {
		klog.Errorf("Failed deleting hybrind overlay port for node %s err: %v", node.Name, err)
	}
}

// AddNode handles node additions
func (m *MasterController) AddNode(node *kapi.Node) error {
	klog.V(5).Infof("Processing add event for node %s", node.Name)
	annotator := kube.NewNodeAnnotator(m.kube, node.Name)

	var allocatedSubnet *net.IPNet
	if houtil.IsHybridOverlayNode(node) {
		var err error
		allocatedSubnet, err = m.hybridOverlayNodeEnsureSubnet(node, annotator)
		if err != nil {
			return fmt.Errorf("failed to update node %q hybrid overlay subnet annotation: %v", node.Name, err)
		}
	} else {
		if err := m.handleOverlayPort(node, annotator); err != nil {
			return fmt.Errorf("failed to set up hybrid overlay logical switch port for %s: %v", node.Name, err)
		}
	}

	if err := annotator.Run(); err != nil {
		// Release allocated subnet if any errors occurred
		if allocatedSubnet != nil {
			_ = m.releaseNodeSubnet(node.Name, allocatedSubnet)
		}
		return fmt.Errorf("failed to set hybrid overlay annotations for %s: %v", node.Name, err)
	}
	return nil
}

// DeleteNode handles node deletions
func (m *MasterController) DeleteNode(node *kapi.Node) error {
	klog.V(5).Infof("Processing node delete for %s", node.Name)
	if subnet, _ := houtil.ParseHybridOverlayHostSubnet(node); subnet != nil {
		if err := m.releaseNodeSubnet(node.Name, subnet); err != nil {
			return err
		}
	}

	if _, ok := node.Annotations[types.HybridOverlayDRMAC]; ok && !houtil.IsHybridOverlayNode(node) {
		m.deleteOverlayPort(node)
	}

	if err := m.removeHybridLRPolicySharedGW(node.Name); err != nil {
		return err
	}
	klog.V(5).Infof("Node delete for %s completed", node.Name)
	return nil
}

func (m *MasterController) setupHybridLRPolicySharedGw(nodeSubnets []*net.IPNet, nodeName string, portMac net.HardwareAddr) error {
	klog.Infof("Setting up logical route policy for hybrid subnet on node: %s", nodeName)
	var L3Prefix string
	for _, nodeSubnet := range nodeSubnets {
		if utilnet.IsIPv6CIDR(nodeSubnet) {
			L3Prefix = "ip6"
		} else {
			L3Prefix = "ip4"
		}
		var hybridCIDR *net.IPNet
		for _, hybridSubnet := range config.HybridOverlay.ClusterSubnets {
			if utilnet.IsIPv6CIDR(hybridSubnet.CIDR) == utilnet.IsIPv6CIDR(nodeSubnet) {
				hybridCIDR = hybridSubnet.CIDR
				break
			}
		}

		drIP := util.GetNodeHybridOverlayIfAddr(nodeSubnet).IP
		matchStr := fmt.Sprintf(`inport == "%s%s" && %s.dst == %s`,
			ovntypes.RouterToSwitchPrefix, nodeName, L3Prefix, hybridCIDR)

		intPriority, _ := strconv.Atoi(ovntypes.HybridOverlaySubnetPriority)

		clusterRouter := nbdb.LogicalRouter{}
		// Logic route policy to steer packet from pod to hybrid overlay nodes
		logicalRouterPolicy := nbdb.LogicalRouterPolicy{
			Priority: intPriority,
			ExternalIDs: map[string]string{
				"name": ovntypes.HybridSubnetPrefix + nodeName,
			},
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{drIP.String()},
			Match:    matchStr,
		}

		// Logic route policy to steer packet from external to nodePort service backed by non-ovnkube pods to hybrid overlay nodes
		logicalPort := ovntypes.RouterToSwitchPrefix + nodeName
		if err := util.CreateMACBinding(m.sbClient, logicalPort, ovntypes.OVNClusterRouter, portMac, drIP); err != nil {
			return fmt.Errorf("failed to create MAC Binding for hybrid overlay: %v", err)
		}
		gwLRPIfAddrs, err := util.GetLRPAddrs(m.nbClient, ovntypes.GWRouterToJoinSwitchPrefix+ovntypes.GWRouterPrefix+nodeName)
		if err != nil {
			return err
		}
		gwLRPIfAddr, err := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(hybridCIDR), gwLRPIfAddrs)
		if err != nil {
			return err
		}
		grMatchStr := fmt.Sprintf(`%s.src == %s && %s.dst == %s`,
			L3Prefix, gwLRPIfAddr.IP.String(), L3Prefix, hybridCIDR)
		grLogicalRouterPolicy := nbdb.LogicalRouterPolicy{
			Priority: intPriority,
			ExternalIDs: map[string]string{
				"name": ovntypes.HybridSubnetPrefix + nodeName + "-gr",
			},
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{drIP.String()},
			Match:    grMatchStr,
		}

		// Static route to steer packets from external to nodePort service backed by pods on hybrid overlay node.
		// This route is to used for triggering above route policy
		clutsterRouterStaticRoutes := nbdb.LogicalRouterStaticRoute{
			IPPrefix: hybridCIDR.String(),
			Nexthop:  drIP.String(),
			ExternalIDs: map[string]string{
				"name": ovntypes.HybridSubnetPrefix + nodeName,
			},
		}

		// Static route to steer packets from external to nodePort service backed by pods on hybrid overlay node to cluster router.
		drLRPIfAddrs, err := util.GetLRPAddrs(m.nbClient, ovntypes.GWRouterToJoinSwitchPrefix+ovntypes.OVNClusterRouter)
		if err != nil {
			return err
		}
		drLRPIfAddr, err := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(hybridCIDR), drLRPIfAddrs)
		if err != nil {
			return fmt.Errorf("failed to match cluster router join interface IPs: %v, err: %v", drLRPIfAddr, err)
		}
		nodeGWRouter := nbdb.LogicalRouter{}
		nodeGWRouterStaticRoutes := nbdb.LogicalRouterStaticRoute{
			IPPrefix: hybridCIDR.String(),
			Nexthop:  drLRPIfAddr.IP.String(),
			ExternalIDs: map[string]string{
				"name": ovntypes.HybridSubnetPrefix + nodeName,
			},
		}
		opModels := []libovsdbops.OperationModel{
			{
				Model: &logicalRouterPolicy,
				ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
					return lrp.Priority == intPriority &&
						lrp.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
				},
				OnModelUpdates: []interface{}{
					&logicalRouterPolicy.Nexthops,
					&logicalRouterPolicy.Match,
				},
				DoAfter: func() {
					clusterRouter.Policies = []string{logicalRouterPolicy.UUID}
				},
			},
			{
				Model: &grLogicalRouterPolicy,
				ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
					return lrp.Priority == intPriority &&
						lrp.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName+"-gr"
				},
				OnModelUpdates: []interface{}{
					&grLogicalRouterPolicy.Nexthops,
					&grLogicalRouterPolicy.Match,
				},
				DoAfter: func() {
					if grLogicalRouterPolicy.UUID != "" {
						clusterRouter.Policies = []string{logicalRouterPolicy.UUID, grLogicalRouterPolicy.UUID}
					}
				},
			},
			{
				Model: &clutsterRouterStaticRoutes,
				ModelPredicate: func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
					return lrsr.IPPrefix == hybridCIDR.String() && lrsr.Nexthop == drIP.String() &&
						lrsr.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
				},
				OnModelUpdates: []interface{}{
					&clutsterRouterStaticRoutes.Nexthop,
					&clutsterRouterStaticRoutes.IPPrefix,
				},
				DoAfter: func() {
					if clutsterRouterStaticRoutes.UUID != "" {
						clusterRouter.StaticRoutes = []string{clutsterRouterStaticRoutes.UUID}
					}
				},
			},
			{
				Model:          &clusterRouter,
				ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovntypes.OVNClusterRouter },
				OnModelMutations: []interface{}{
					&clusterRouter.StaticRoutes,
					&clusterRouter.Policies,
				},
				ErrNotFound: true,
			},
			{
				Model: &nodeGWRouterStaticRoutes,
				ModelPredicate: func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
					return lrsr.IPPrefix == hybridCIDR.String() && lrsr.Nexthop == drLRPIfAddr.IP.String() &&
						lrsr.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
				},
				OnModelUpdates: []interface{}{
					&nodeGWRouterStaticRoutes.Nexthop,
					&nodeGWRouterStaticRoutes.IPPrefix,
				},
				DoAfter: func() {
					if nodeGWRouterStaticRoutes.UUID != "" {
						nodeGWRouter.StaticRoutes = []string{nodeGWRouterStaticRoutes.UUID}
					}
				},
			},
			{
				Model: &nodeGWRouter,
				ModelPredicate: func(lr *nbdb.LogicalRouter) bool {
					return lr.Name == fmt.Sprintf("GR_%s", nodeName)
				},
				OnModelMutations: []interface{}{
					&nodeGWRouter.StaticRoutes,
				},
				ErrNotFound: true,
			},
		}
		if _, err := m.modelClient.CreateOrUpdate(opModels...); err != nil {
			return fmt.Errorf("failed to add policy route for host %q on %s , error: %v", nodeName, ovntypes.OVNClusterRouter, err)
		}
		klog.Infof("Created hybrid overlay logical route policies and static routes for node %s", nodeName)
	}
	return nil
}

func (m *MasterController) removeHybridLRPolicySharedGW(nodeName string) error {
	gwRouterName := fmt.Sprintf("GR_%s", nodeName)
	clusterRouter := nbdb.LogicalRouter{}
	nodeGWRouter := nbdb.LogicalRouter{}
	clusterRouterPolicyRes := []nbdb.LogicalRouterPolicy{}
	gwNodeRouterStaticRouteRes := []nbdb.LogicalRouterStaticRoute{}
	clutsterlRouterStaticRouteRes := []nbdb.LogicalRouterStaticRoute{}
	opModels := []libovsdbops.OperationModel{
		{
			ModelPredicate: func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
				return lrsr.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
			},
			ExistingResult: &gwNodeRouterStaticRouteRes,
			DoAfter: func() {
				nodeGWRouter.StaticRoutes = libovsdbops.ExtractUUIDsFromModels(&gwNodeRouterStaticRouteRes)
			},
			BulkOp: true,
		},
		{
			Model:          &nodeGWRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == gwRouterName },
			OnModelMutations: []interface{}{
				&nodeGWRouter.StaticRoutes,
			},
		},
		{
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
			},
			ExistingResult: &clusterRouterPolicyRes,
			DoAfter: func() {
				clusterRouter.Policies = libovsdbops.ExtractUUIDsFromModels(&clusterRouterPolicyRes)
			},
			BulkOp: true,
		},
		{
			ModelPredicate: func(lrp *nbdb.LogicalRouterPolicy) bool {
				return lrp.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName+"-gr"
			},
			ExistingResult: &clusterRouterPolicyRes,
			DoAfter: func() {
				clusterRouter.Policies = libovsdbops.ExtractUUIDsFromModels(&clusterRouterPolicyRes)
			},
			BulkOp: true,
		},
		{
			Model:          &clusterRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovntypes.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&clusterRouter.Policies,
			},
		},
		{
			ModelPredicate: func(lrsr *nbdb.LogicalRouterStaticRoute) bool {
				return lrsr.ExternalIDs["name"] == ovntypes.HybridSubnetPrefix+nodeName
			},
			ExistingResult: &clutsterlRouterStaticRouteRes,
			DoAfter: func() {
				clusterRouter.StaticRoutes = libovsdbops.ExtractUUIDsFromModels(&clutsterlRouterStaticRouteRes)
			},
			BulkOp: true,
		},
		{
			Model:          &clusterRouter,
			ModelPredicate: func(lr *nbdb.LogicalRouter) bool { return lr.Name == ovntypes.OVNClusterRouter },
			OnModelMutations: []interface{}{
				&clusterRouter.StaticRoutes,
			},
		},
	}
	if err := m.modelClient.Delete(opModels...); err != nil {
		return fmt.Errorf("failed to delete policies and static routes from %s and %s, error: %v", ovntypes.OVNClusterRouter, gwRouterName, err)
	}
	return nil
}
