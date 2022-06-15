package controller

import (
	"context"
	"net"
	"sync"

	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func appHONRun(app *cli.App, netns ns.NetNS) {
	_ = netns.Do(func(ns.NetNS) error {
		defer GinkgoRecover()
		err := app.Run([]string{
			app.Name,
			"-no-hostsubnet-nodes=" + v1.LabelOSStable + "=linux",
		})
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
}

var _ = Describe("Hybrid Overlay Node Linux Operations", func() {
	var (
		app      *cli.App
		netns    ns.NetNS
		stopChan chan struct{}
		wg       *sync.WaitGroup
		err      error
	)
	testNodeName := "worker-1"

	BeforeEach(func() {
		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}

		netns, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// prepare eth0 in original namespace
		_ = netns.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Set up default interface
			link := ovntest.AddLink("eth0")
			drMAC, err := net.ParseMAC(testDRMAC)
			Expect(err).NotTo(HaveOccurred())
			netlink.LinkSetHardwareAddr(link, drMAC)
			Expect(err).NotTo(HaveOccurred())
			nodeIP, err := netlink.ParseAddr(testNodeIP + "/24")
			Expect(err).NotTo(HaveOccurred())
			netlink.AddrAdd(link, nodeIP)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})

	AfterEach(func() {
		close(stopChan)
		wg.Wait()
		Expect(netns.Close()).To(Succeed())
		Expect(testutils.UnmountNS(netns)).To(Succeed())
	})

	ovntest.OnSupportedPlatformsIt("Set VTEP and gateway MAC address to its own node object annotations", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := config.InitConfig(ctx, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			testNode := createNode(testNodeName, "linux", testNodeIP, map[string]string{
				types.HybridOverlayNodeSubnet: testNodeSubnet,
			})

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*testNode,
				},
			})

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				testNodeName,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.AddNode(testNode)
			Expect(err).NotTo(HaveOccurred())
			f.WaitForCacheSync(stopChan)

			Eventually(func() (map[string]string, error) {
				updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), testNodeName, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 2).Should(HaveKeyWithValue(types.HybridOverlayDRMAC, testDRMAC))
			return nil
		}
		appHONRun(app, netns)
	})

	ovntest.OnSupportedPlatformsIt("Remove ovnkube annotations for pod on Hybrid Overlay node", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := config.InitConfig(ctx, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			testPod1 := createPod("default", "testpod-1", testNodeName, "2.2.3.5/24", "aa:bb:cc:dd:ee:ff")
			testPod2 := createPod("default", "testpod-2", "other-worker", "2.2.3.6/24", "ab:bb:cc:dd:ee:ff")
			testNode := createNode(testNodeName, "linux", testNodeIP, map[string]string{
				types.HybridOverlayNodeSubnet: testNodeSubnet,
			})

			fakeClient := fake.NewSimpleClientset(&v1.PodList{
				Items: []v1.Pod{
					*testPod1,
					*testPod2,
				},
			}, &v1.NodeList{
				Items: []v1.Node{
					*testNode,
				},
			})

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				testNodeName,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.AddNode(testNode)
			Expect(err).NotTo(HaveOccurred())
			err = n.controller.AddPod(testPod1)
			Expect(err).NotTo(HaveOccurred())
			err = n.controller.AddPod(testPod2)
			Expect(err).NotTo(HaveOccurred())
			f.WaitForCacheSync(stopChan)

			Eventually(func() (map[string]string, error) {
				updatedPod, err := fakeClient.CoreV1().Pods("default").Get(context.TODO(), "testpod-1", metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedPod.Annotations, nil
			}, 2).ShouldNot(HaveKey(util.OvnPodAnnotationName))

			Eventually(func() (map[string]string, error) {
				updatedPod, err := fakeClient.CoreV1().Pods("default").Get(context.TODO(), "testpod-2", metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedPod.Annotations, nil
			}, 2).Should(HaveKey(util.OvnPodAnnotationName))
			return nil
		}
		appHONRun(app, netns)
	})
})
