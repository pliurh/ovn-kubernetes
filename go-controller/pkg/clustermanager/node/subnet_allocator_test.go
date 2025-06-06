package node

import (
	"fmt"
	"net"
	"testing"

	utilnet "k8s.io/utils/net"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
)

const testNodeName string = "test"

func newSubnetAllocator(clusterCIDR string, hostSubnetLen int) (SubnetAllocator, error) {
	sna := NewSubnetAllocator()
	return sna, sna.AddNetworkRange(ovntest.MustParseIPNet(clusterCIDR), hostSubnetLen)
}

func networkID(n int) string {
	if n == -1 {
		return "network"
	} else {
		return fmt.Sprintf("network %d", n)
	}
}

func allocateOneNetwork(sna SubnetAllocator, owner string) (*net.IPNet, error) {
	sns, err := sna.AllocateNetworks(owner)
	if err != nil {
		return nil, err
	}
	if len(sns) != 1 {
		return nil, fmt.Errorf("unexpectedly got multiple subnets: %v", sns)
	}
	return sns[0], nil
}

func allocateExpected(sna SubnetAllocator, n int, expected ...string) error {
	// Canonicalize expected; eg "fd01:0:0:0::/64" -> "fd01::/64"
	for i, str := range expected {
		expected[i] = ovntest.MustParseIPNet(str).String()
	}

	sns, err := sna.AllocateNetworks(fmt.Sprintf("%s-%d", testNodeName, n))
	if err != nil {
		return fmt.Errorf("failed to allocate %s (%s): %v", networkID(n), expected, err)
	}
	if len(sns) != len(expected) {
		return fmt.Errorf("wrong number of networks for %s: expected %d, got %d", networkID(n), len(expected), len(sns))
	}
	for i := range sns {
		if sns[i].String() != expected[i] {
			return fmt.Errorf("failed to allocate %s: expected %s, got %s", networkID(n), expected[i], sns[i].String())
		}
	}
	return nil
}

func allocateNotExpected(sna SubnetAllocator, v4n, v6n int) error {
	if sns, err := sna.AllocateNetworks(testNodeName); err == nil {
		return fmt.Errorf("unexpectedly succeeded in allocating v4=%s, v6=%s (sns=%v)", networkID(v4n), networkID(v6n), sns)
	} else if err != ErrSubnetAllocatorFull {
		return fmt.Errorf("returned error was not ErrSubnetAllocatorFull (%v)", err)
	}

	v4used, v6used := sna.Usage()
	if v4n >= 0 && v4used != uint64(v4n) {
		return fmt.Errorf("expected %d available v4 subnets but got %d", v4n, v4used)
	}
	if v6n >= 0 && v6used != uint64(v6n) {
		return fmt.Errorf("expected %d available v6 subnets but got %d", v6n, v6used)
	}
	return nil
}

func expectNumSubnets(sna SubnetAllocator, v4expected, v6expected uint64) error {
	v4count, v6count := sna.Count()
	if v4count != v4expected {
		return fmt.Errorf("expected %d available v4 subnets but got %d", v4expected, v4count)
	}
	if v6count != v6expected {
		return fmt.Errorf("expected %d available v6 subnets but got %d", v6expected, v6count)
	}
	return nil
}

// 10.1.ssssssss.hhhhhhhh
func TestAllocateSubnetIPv4(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 24)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 256, 0); err != nil {
		t.Fatal(err)
	}

	for n := 0; n < 256; n++ {
		if err := allocateExpected(sna, n, fmt.Sprintf("10.1.%d.0/24", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocateNotExpected(sna, 256, 0); err != nil {
		t.Fatal(err)
	}
}

// fd01:0:0:SSSS:HHHH:HHHH:HHHH:HHHH
func TestAllocateSubnetIPv6(t *testing.T) {
	sna, err := newSubnetAllocator("fd01::/48", 64)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 0, 65536); err != nil {
		t.Fatal(err)
	}

	// IPv6 allocation skips the 0 subnet, so we start with n=1
	for n := 1; n < 256; n++ {
		if err := allocateExpected(sna, n, fmt.Sprintf("fd01:0:0:%x::/64", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocateExpected(sna, 256, "fd01:0:0:100::/64"); err != nil {
		t.Fatal(err)
	}

	// We have 16 bits for subnet, after which it will wrap around (and then allocate
	// the next previously-unallocated value, skipping the 0 subnet again).
	baseSNA := sna.(*BaseSubnetAllocator)
	baseSNA.v6ranges[0].next = 0xFFFF
	if err := allocateExpected(sna, -1, "fd01:0:0:ffff::/64"); err != nil {
		t.Fatal(err)
	}
	if err := allocateExpected(sna, -2, "fd01:0:0:101::/64"); err != nil {
		t.Fatal(err)
	}
}

// 10.1.sssssshh.hhhhhhhh
func TestAllocateSubnetLargeHostBitsIPv4(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 22)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 64, 0); err != nil {
		t.Fatal(err)
	}

	for n := 0; n < 64; n++ {
		if err := allocateExpected(sna, n, fmt.Sprintf("10.1.%d.0/22", n*4)); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocateNotExpected(sna, 64, 0); err != nil {
		t.Fatal(err)
	}
}

// fd01:0:0:SSSH:HHHH:HHHH:HHHH:HHHH
func TestAllocateSubnetLargeHostBitsIPv6(t *testing.T) {
	sna, err := newSubnetAllocator("fd01::/48", 60)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 0, 4096); err != nil {
		t.Fatal(err)
	}

	// (Because of the small subnet size we won't skip the 0 subnet like in the
	// other IPv6 cases.)
	for n := 0; n < 256; n++ {
		if err := allocateExpected(sna, n, fmt.Sprintf("fd01:0:0:%x::/60", n<<4)); err != nil {
			t.Fatal(err)
		}
	}
}

// 10.1.ssssssss.sshhhhhh
func TestAllocateSubnetLargeSubnetBitsIPv4(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 26)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 1024, 0); err != nil {
		t.Fatal(err)
	}

	// for IPv4, we tweak the allocation order and expect to see all of the ".0"
	// networks before any non-".0" network
	for n := 0; n < 256; n++ {
		if err = allocateExpected(sna, n, fmt.Sprintf("10.1.%d.0/26", n)); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 256; n++ {
		if err = allocateExpected(sna, n+256, fmt.Sprintf("10.1.%d.64/26", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err = allocateExpected(sna, 512, "10.1.0.128/26"); err != nil {
		t.Fatal(err)
	}

	baseSNA := sna.(*BaseSubnetAllocator)
	baseSNA.v4ranges[0].next = 1023
	if err = allocateExpected(sna, -1, "10.1.255.192/26"); err != nil {
		t.Fatal(err)
	}
	// Next allocation should wrap around and get the next unallocated network (513)
	if err = allocateExpected(sna, -2, "10.1.1.128/26"); err != nil {
		t.Fatalf("After wraparound: %v", err)
	}
}

// fd01:0:0:SSSS:SSSS:SHHH:HHHH:HHHH
func TestAllocateSubnetLargeSubnetBitsIPv6(t *testing.T) {
	sna, err := newSubnetAllocator("fd01::/48", 84)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 0, 68719476736); err != nil {
		t.Fatal(err)
	}

	// For IPv6 we expect to see the networks just get allocated in order
	for n := 1; n < 256; n++ {
		// (Many of the IPv6 strings we Sprintf here won't be in canonical
		// format, but allocateExpecting() will fix them for us.)
		if err := allocateExpected(sna, n, fmt.Sprintf("fd01:0:0:0:%x:%x::/84", n>>4, (n<<12)&0xFFFF)); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocateExpected(sna, -1, "fd01:0:0:0:10:0::/84"); err != nil {
		t.Fatal(err)
	}

	// Even though we theoretically have 36 bits of subnets, SubnetAllocator will only
	// use the lower 24 bits before looping around and then allocating the next
	// previously-unallocated subnet.
	baseSNA := sna.(*BaseSubnetAllocator)
	baseSNA.v6ranges[0].next = 0x00FFFFFF
	if err := allocateExpected(sna, -2, "fd01:0:0:000f:ffff:f000::/84"); err != nil {
		t.Fatal(err)
	}
	if err := allocateExpected(sna, -3, "fd01:0:0:0:10:1000::/84"); err != nil {
		t.Fatal(err)
	}
}

// 10.000000ss.sssssshh.hhhhhhhh
func TestAllocateSubnetOverlappingIPv4(t *testing.T) {
	sna, err := newSubnetAllocator("10.0.0.0/14", 22)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	if err := expectNumSubnets(sna, 256, 0); err != nil {
		t.Fatal(err)
	}

	for n := 0; n < 4; n++ {
		if err = allocateExpected(sna, n, fmt.Sprintf("10.%d.0.0/22", n)); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 4; n++ {
		if err = allocateExpected(sna, n+4, fmt.Sprintf("10.%d.4.0/22", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocateExpected(sna, 8, "10.0.8.0/22"); err != nil {
		t.Fatal(err)
	}

	baseSNA := sna.(*BaseSubnetAllocator)
	baseSNA.v4ranges[0].next = 255
	if err := allocateExpected(sna, -1, "10.3.252.0/22"); err != nil {
		t.Fatal(err)
	}
	if err := allocateExpected(sna, -2, "10.1.8.0/22"); err != nil {
		t.Fatalf("After wraparound: %v", err)
	}
}

// There's no TestAllocateSubnetOverlappingIPv6 because it wouldn't be any different from
// TestAllocateSubnetLargeSubnetBitsIPv6.

// 10.1.hhhhhhhh.hhhhhhhh
func TestAllocateSubnetNoSubnetBitsIPv4(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 16)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	if err := allocateExpected(sna, 0, "10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := allocateNotExpected(sna, 1, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateSubnetNoSubnetBitsIPv6(t *testing.T) {
	// fd01:0:0:0:HHHH:HHHH:HHHH:HHHH
	sna, err := newSubnetAllocator("fd01::/64", 64)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	if err := allocateExpected(sna, 0, "fd01::/64"); err != nil {
		t.Fatal(err)
	}
	if err := allocateNotExpected(sna, 0, 1); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateSubnetInvalidHostBitsOrCIDR(t *testing.T) {
	_, err := newSubnetAllocator("10.1.0.0/16", 14)
	if err == nil {
		t.Fatal("Unexpectedly succeeded in initializing subnet allocator")
	}

	_, err = newSubnetAllocator("10.1.0.0/16", 32)
	if err == nil {
		t.Fatal("Unexpectedly succeeded in initializing subnet allocator")
	}

	_, err = newSubnetAllocator("fd01::/64", 62)
	if err == nil {
		t.Fatal("Unexpectedly succeeded in initializing subnet allocator")
	}

	_, err = newSubnetAllocator("fd01::/64", 128)
	if err == nil {
		t.Fatal("Unexpectedly succeeded in initializing subnet allocator")
	}
}

func TestMarkAllocatedNetwork(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	allocSubnets := make([]*net.IPNet, 4)
	for i := 0; i < 4; i++ {
		if allocSubnets[i], err = allocateOneNetwork(sna, fmt.Sprintf("%s-%d", testNodeName, i)); err != nil {
			t.Fatal("Failed to allocate network: ", err)
		}
	}

	if sn, err := allocateOneNetwork(sna, testNodeName); err == nil {
		t.Fatalf("Unexpectedly succeeded in allocating network (sn=%s)", sn.String())
	}
	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 2), allocSubnets[2]); err != nil {
		t.Fatalf("Failed to release the subnet (allocSubnets[2]=%s): %v", allocSubnets[2].String(), err)
	}
	for i := 0; i < 2; i++ {
		if err := sna.MarkAllocatedNetworks(fmt.Sprintf("%s-%d", testNodeName, 2), allocSubnets[2]); err != nil {
			t.Fatalf("Failed to mark allocated subnet (allocSubnets[2]=%s): %v", allocSubnets[2].String(), err)
		}
	}
	if sn, err := allocateOneNetwork(sna, testNodeName); err == nil {
		t.Fatalf("Unexpectedly succeeded in allocating network (sn=%s)", sn.String())
	}

	// Test subnet that does not belong to network
	subnet := ovntest.MustParseIPNet("10.2.3.0/24")
	if err := sna.MarkAllocatedNetworks(testNodeName, subnet); err == nil {
		t.Fatalf("Unexpectedly succeeded in marking allocated subnet that doesn't belong to network (sn=%s)", subnet.String())
	}
}

func TestMarkAllocatedNetworkDifferentOwner(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	allocSubnets := make([]*net.IPNet, 4)
	for i := 0; i < 4; i++ {
		if allocSubnets[i], err = allocateOneNetwork(sna, fmt.Sprintf("%s-%d", testNodeName, i)); err != nil {
			t.Fatal("Failed to allocate network: ", err)
		}
	}
	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 2), allocSubnets[2]); err != nil {
		t.Fatalf("Failed to release the subnet (allocSubnets[2]=%s): %v", allocSubnets[2].String(), err)
	}

	// Try to reserve two subnets, only one of which should be free
	if err := sna.MarkAllocatedNetworks("thief", allocSubnets[2], allocSubnets[3]); err == nil {
		t.Fatalf("Unexpectedly succeeded in marking already allocated subnets (sn[2]=%s, sn[3]=%s)",
			allocSubnets[2].String(), allocSubnets[3].String())
	}

	// Ensure that the first requested subnet [2] was not allocated by attempting to
	// mark it with a 3rd owner, which should succeed
	if err := sna.MarkAllocatedNetworks("blah", allocSubnets[2]); err != nil {
		t.Fatalf("Failed to mark allocated subnet (sn[2]=%s): %v", allocSubnets[2].String(), err)
	}
	// Undo the test allocation and original conflicting allocation
	if err := sna.ReleaseNetworks("blah", allocSubnets[2]); err != nil {
		t.Fatalf("Failed to release the subnet (allocSubnets[2]=%s): %v",
			allocSubnets[2].String(), err)
	}
	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 3), allocSubnets[3]); err != nil {
		t.Fatalf("Failed to release the subnet (allocSubnets[3]=%s): %v",
			allocSubnets[3].String(), err)
	}

	// Try again
	if err := sna.MarkAllocatedNetworks("thief", allocSubnets[2], allocSubnets[3]); err != nil {
		t.Fatalf("Failed to mark allocated subnet (sn[2]=%s, sn[3]=%s): %v",
			allocSubnets[2].String(), allocSubnets[3].String(), err)
	}
}

func TestReleaseNetworks(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	// Allocate and release for one node
	sn, err := allocateOneNetwork(sna, testNodeName)
	if err != nil {
		t.Fatal("Failed to allocate network: ", err)
	}
	if err := sna.ReleaseNetworks(testNodeName, sn); err != nil {
		t.Fatalf("Failed to release the subnet (allocSubnets[2]=%s): %v", sn.String(), err)
	}

	// Allocate but try to release from another owner
	sn, err = allocateOneNetwork(sna, testNodeName)
	if err != nil {
		t.Fatal("Failed to allocate network: ", err)
	}
	if err := sna.ReleaseNetworks("thief", sn); err == nil {
		t.Fatalf("Unexpectedly able to release other network %s", sn.String())
	}
	// Verify it's still allocated by original owner
	if err := sna.MarkAllocatedNetworks("thief", sn); err == nil {
		t.Fatalf("Unexpectedly able to mark other network %s", sn.String())
	}
}

func TestAllocateReleaseSubnet(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}

	var releaseSn *net.IPNet

	for i := 0; i < 4; i++ {
		sn, err := allocateOneNetwork(sna, fmt.Sprintf("%s-%d", testNodeName, i))
		if err != nil {
			t.Fatal("Failed to allocate network: ", err)
		}
		if sn.String() != fmt.Sprintf("10.1.%d.0/18", i*64) {
			t.Fatalf("Did not get expected subnet (i=%d, sn=%s)", i, sn.String())
		}
		if i == 2 {
			releaseSn = sn
		}
	}

	sn, err := allocateOneNetwork(sna, testNodeName)
	if err == nil {
		t.Fatalf("Unexpectedly succeeded in allocating network (sn=%s)", sn.String())
	}

	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 2), releaseSn); err != nil {
		t.Fatalf("Failed to release the subnet (releaseSn=%s): %v", releaseSn, err)
	}

	sn, err = allocateOneNetwork(sna, testNodeName)
	if err != nil {
		t.Fatal("Failed to allocate network: ", err)
	}
	if sn.String() != releaseSn.String() {
		t.Fatalf("Did not get expected subnet (sn=%s)", sn.String())
	}

	sn, err = allocateOneNetwork(sna, fmt.Sprintf("%s-%s", testNodeName, "extra"))
	if err == nil {
		t.Fatalf("Unexpectedly succeeded in allocating network (sn=%s)", sn.String())
	}
}

func TestMultipleSubnets(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	err = sna.AddNetworkRange(ovntest.MustParseIPNet("10.2.0.0/16"), 18)
	if err != nil {
		t.Fatal("Failed to add network range: ", err)
	}

	for i := 0; i < 4; i++ {
		if err := allocateExpected(sna, i, fmt.Sprintf("10.1.%d.0/18", i*64)); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 4; i++ {
		if err := allocateExpected(sna, i+4, fmt.Sprintf("10.2.%d.0/18", i*64)); err != nil {
			t.Fatal(err)
		}
	}

	if err := allocateNotExpected(sna, 8, 0); err != nil {
		t.Fatal(err)
	}

	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 2),
		ovntest.MustParseIPNet("10.1.128.0/18"),
	); err != nil {
		t.Fatal(err)
	}
	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 6),
		ovntest.MustParseIPNet("10.2.128.0/18"),
	); err != nil {
		t.Fatal(err)
	}

	if err := allocateExpected(sna, -1, "10.1.128.0/18"); err != nil {
		t.Fatal(err)
	}
	if err := allocateExpected(sna, -2, "10.2.128.0/18"); err != nil {
		t.Fatal(err)
	}

	if err := allocateNotExpected(sna, -1, 0); err != nil {
		t.Fatal(err)
	}
}

func TestDualStack(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	err = sna.AddNetworkRange(ovntest.MustParseIPNet("10.2.0.0/16"), 18)
	if err != nil {
		t.Fatal("Failed to add network range: ", err)
	}
	err = sna.AddNetworkRange(ovntest.MustParseIPNet("fd01::/48"), 64)
	if err != nil {
		t.Fatal("Failed to add network range: ", err)
	}

	for i := 0; i < 4; i++ {
		if err := allocateExpected(sna, i,
			fmt.Sprintf("10.1.%d.0/18", i*64),
			fmt.Sprintf("fd01:0:0:%x::/64", i+1),
		); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		if err := allocateExpected(sna, i+4,
			fmt.Sprintf("10.2.%d.0/18", i*64),
			fmt.Sprintf("fd01:0:0:%x::/64", i+5),
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := allocateNotExpected(sna, 8, 8); err != nil {
		t.Fatal(err)
	}

	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 2),
		ovntest.MustParseIPNet("10.1.128.0/18"),
		ovntest.MustParseIPNet("fd01:0:0:3::/64"),
	); err != nil {
		t.Fatal(err)
	}

	if err := sna.ReleaseNetworks(fmt.Sprintf("%s-%d", testNodeName, 6),
		ovntest.MustParseIPNet("10.2.128.0/18"),
		ovntest.MustParseIPNet("fd01:0:0:7::/64"),
	); err != nil {
		t.Fatal(err)
	}

	// The IPv4 subnetallocator will now reuse the freed subnets (since they're all it has
	// left), but the IPv6 subnetallocator will continue allocating new ones.
	if err := allocateExpected(sna, -1, "10.1.128.0/18", "fd01:0:0:9::/64"); err != nil {
		t.Fatal(err)
	}
	if err := allocateExpected(sna, -2, "10.2.128.0/18", "fd01:0:0:a::/64"); err != nil {
		t.Fatal(err)
	}

	if err := allocateNotExpected(sna, -1, -1); err != nil {
		t.Fatal(err)
	}
}

// Allocating multiple subnet from same Clusternetwork CIDR for
// a node should not be allowed
func TestAllocateSubnetSameOwner(t *testing.T) {
	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	err = sna.AddNetworkRange(ovntest.MustParseIPNet("fd01::/48"), 64)
	if err != nil {
		t.Fatal("Failed to add network range: ", err)
	}

	sn1, err := sna.AllocateNetworks(fmt.Sprintf("%s-%d", testNodeName, 0))
	if err != nil {
		t.Fatalf("Failed to allocate subnet: %s", err)
	}
	sn2, err := sna.AllocateNetworks(fmt.Sprintf("%s-%d", testNodeName, 0))
	if err != nil {
		t.Fatalf("Failed to allocate subnet: %s", err)
	}
	for _, i := range sn1 {
		for _, j := range sn2 {
			if utilnet.IPFamilyOf(i.IP) == utilnet.IPFamilyOf(j.IP) && i.String() != j.String() {
				t.Fatalf("Unexpectedly allocated another subnet for node name: %s", fmt.Sprintf("%s-%d", testNodeName, 0))
			}
		}
	}
}

func TestListAllNetworks(t *testing.T) {
	expectV4Subnets := []string{
		"10.1.0.0/18",
		"10.1.64.0/18",
		"10.1.128.0/18",
		"10.1.192.0/18",
	}
	expectV6Subnets := []string{
		"fd01::/64",
		"fd01:0:0:1::/64",
		"fd01:0:0:2::/64",
		"fd01:0:0:3::/64",
	}

	sna, err := newSubnetAllocator("10.1.0.0/16", 18)
	if err != nil {
		t.Fatal("Failed to initialize subnet allocator: ", err)
	}
	err = sna.AddNetworkRange(ovntest.MustParseIPNet("fd01::/62"), 64)
	if err != nil {
		t.Fatal("Failed to add network range: ", err)
	}

	v4Subnets := sna.ListAllIPv4Networks()
	if len(v4Subnets) != len(expectV4Subnets) {
		t.Fatalf("Expected %d subnets, got %d", len(expectV4Subnets), len(v4Subnets))
	}
	for i, sn := range v4Subnets {
		if sn.String() != expectV4Subnets[i] {
			t.Fatalf("Expected %s, got %s", expectV4Subnets[i], sn.String())
		}
	}

	v6Subnets := sna.ListAllIPv6Networks()
	if len(v6Subnets) != len(expectV6Subnets) {
		t.Fatalf("Expected %d subnets, got %d", len(expectV6Subnets), len(v6Subnets))
	}
	for i, sn := range v6Subnets {
		if sn.String() != expectV6Subnets[i] {
			t.Fatalf("Expected %s, got %s", expectV6Subnets[i], sn.String())
		}
	}
}
