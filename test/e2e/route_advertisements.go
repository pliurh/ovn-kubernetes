package e2e

import (
	"context"
	// "encoding/json"
	"fmt"
	"math/rand"
	"strings"

	//	"regexp"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	//	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"

	// rav1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
)

func ensureRoutes() {
    // Get all routes
    routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
    if err != nil {
        framework.Logf("Failed to list routes: %v", err)
    }

    // Print each route
    for _, route := range routes {
        fmt.Printf("Route: %+v\n", route)
    }
}

var _ = ginkgo.Describe("Pod to external server when podNetwork advertised", func() {
	const (
		echoServerPodNameTemplate = "echo-server-pod-%d"
		echoClientPodName         = "echo-client-pod"
		echoServerPodPortMin      = 9800
		echoServerPodPortMax      = 9899
		primaryNetworkName        = "kind"
	)

	f := wrappedTestFramework("pod2external-route-advertisements")
	cleanupFn := func() {}

	ginkgo.AfterEach(func() {
		cleanupFn()
	})

	// The below series of tests queries a server running as a hostNetwork:true pod on nodeB from a client pod running as hostNetwork:false on nodeA
	// This traffic scenario mimics a pod2external setup where large packets and needs frag is involved.
	// for both HTTP and UDP and different ingress and egress payload sizes.
	// Steps:
	// * Set up a hostNetwork:false client pod (agnhost echo server) on nodeA
	// * Set up a external docker container as a server
	// * Query from client pod to server pod
	// Traffic Flow:
	// Req: podA on nodeA -> nodeA switch -> nodeA cluster-route -> nodeA transit switch -> nodeA join switch -> nodeA GR -> nodeA ext switch -> nodeA br-ex -> underlay
	// underlay -> server
	// Res: server sends large packet -> br-ex on nodeA -> nodeA ext-switch -> rtoe-GR port sends back needs frag thanks to gateway_mtu option
	// ICMP needs frag goes back to external server
	// server now fragments packets correctly.
	// NOTE: on LGW, the pkt exits via mp0 on nodeA and path is different than what is described above
	// Frag needed is sent by nodeA using ovn-k8s-mp0 interface mtu and not OVN's GR for flows where services are not involved in LGW
	ginkgo.When("a client ovnk pod targeting an external server is created", func() {
		var serverPodPort int
		var serverPodName string
		var serverNodeInternalIPs []string

		var clientPod *v1.Pod
		var clientPodNodeName string

		ginkgo.BeforeEach(func() {
			if !isDefaultNetworkAdvertised() {
				e2eskipper.Skipf(
					"skipping pod to external server tests when podNetwork is not advertised",
				)
			}
			ginkgo.By("Selecting 3 schedulable nodes")
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(context.TODO(), f.ClientSet, 3)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(len(nodes.Items)).To(gomega.BeNumerically(">", 2))

			ginkgo.By("Selecting nodes for client pod and server host-networked pod")
			clientPodNodeName = nodes.Items[1].Name

			ginkgo.By("Creating hostNetwork:false (ovnk) client pod")
			clientPod = e2epod.NewAgnhostPod(f.Namespace.Name, echoClientPodName, nil, nil, nil)
			clientPod.Spec.NodeName = clientPodNodeName
			for k := range clientPod.Spec.Containers {
				if clientPod.Spec.Containers[k].Name == "agnhost-container" {
					clientPod.Spec.Containers[k].Command = []string{
						"sleep",
						"infinity",
					}
				}
			}
			e2epod.NewPodClient(f).CreateSync(context.TODO(), clientPod)

			ginkgo.By("Creating the external server")
			serverPodPort = rand.Intn(echoServerPodPortMax-echoServerPodPortMin) + echoServerPodPortMin
			serverPodName = fmt.Sprintf(echoServerPodNameTemplate, serverPodPort)
			framework.Logf("Creating server pod listening on TCP and UDP port %d", serverPodPort)
			agntHostCmds := []string{"netexec", "--http-port", fmt.Sprintf("%d", serverPodPort), "--udp-port", fmt.Sprintf("%d", serverPodPort)}
			framework.Logf("Creating server pod attaching to the frr container network")
			externalIpv4, externalIpv6 := createClusterExternalContainer(serverPodName, agnhostImage,
				[]string{"--network", "container:frr", "-P", "--cap-add", "NET_ADMIN"},
				agntHostCmds,
			)

			if isIPv4Supported() {
				serverNodeInternalIPs = append(serverNodeInternalIPs, externalIpv4)
			}

			if isIPv6Supported() {
				serverNodeInternalIPs = append(serverNodeInternalIPs, externalIpv6)
			}
			gomega.Expect(len(serverNodeInternalIPs)).To(gomega.BeNumerically(">", 0))
		})

		ginkgo.AfterEach(func() {
			ginkgo.By("Removing external container")
			if len(serverPodName) > 0 {
				deleteClusterExternalContainer(serverPodName)
			}
		})

		ginkgo.When("tests are run towards the external agnhost echo server", func() {
			ginkgo.It("routes to the default pod network shall be advertised to external", func() {
				// Check if the default podNetwork route advertisement is enabled
				// ra := &rav1.RouteAdvertisements{}
				// raRaw, err := e2ekubectl.RunKubectl("", "get", "ra", "default", "-o", "json")
				// gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// err = json.Unmarshal([]byte(raRaw), &ra)
				// gomega.Expect(err).NotTo(gomega.HaveOccurred())
				// gomega.Expect(ra.Status.Status).To(gomega.Equal("Accepted"))
				// gomega.Expect(ra.Spec.Advertisements.PodNetwork).To(gomega.BeTrue())

				isAdvertised, err := e2ekubectl.RunKubectl("", "get", "ra", "default", "--template={{.spec.advertisements.podNetwork}}")
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(isAdvertised).To(gomega.Equal("true"))

				status, err := e2ekubectl.RunKubectl("", "get", "ra", "default", "--template={{.status.status}}")
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(status).To(gomega.Equal("Accepted"))
			})

			ginkgo.It("queries to the external server shall not be SNATed", func() {
				podIP := getPodAddress(clientPod.Name, clientPod.Namespace)
				framework.Logf("get client pod IP address %s", podIP)
				for _, serverNodeIP := range serverNodeInternalIPs {
					ginkgo.By(fmt.Sprintf("Sending request to node IP %s "+
						"and expecting to receive the same payload", serverNodeIP))
					cmd := fmt.Sprintf("curl --max-time 10 -g -q -s http://%s:%d/clientip",
						serverNodeIP,
						serverPodPort,
					)
					framework.Logf("Testing pod to external traffic with command %q", cmd)
					stdout, err := e2epodoutput.RunHostCmdWithRetries(
						clientPod.Namespace,
						clientPod.Name,
						cmd,
						framework.Poll,
						60*time.Second)
					framework.ExpectNoError(err, fmt.Sprintf("Testing pod to external traffic failed: %v", err))
					gomega.Expect(strings.Split(stdout, ":")[0]).To(gomega.Equal(podIP), fmt.Sprintf("Testing pod to external traffic failed"))
				}
			})
		})
	})
})
