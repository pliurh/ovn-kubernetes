// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package sbdb

import "github.com/ovn-org/libovsdb/model"

const IGMPGroupTable = "IGMP_Group"

// IGMPGroup defines an object in IGMP_Group table
type IGMPGroup struct {
	UUID     string   `ovsdb:"_uuid"`
	Address  string   `ovsdb:"address"`
	Chassis  *string  `ovsdb:"chassis"`
	Datapath *string  `ovsdb:"datapath"`
	Ports    []string `ovsdb:"ports"`
}

func (a *IGMPGroup) GetUUID() string {
	return a.UUID
}

func (a *IGMPGroup) GetAddress() string {
	return a.Address
}

func (a *IGMPGroup) GetChassis() *string {
	return a.Chassis
}

func copyIGMPGroupChassis(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalIGMPGroupChassis(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *IGMPGroup) GetDatapath() *string {
	return a.Datapath
}

func copyIGMPGroupDatapath(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalIGMPGroupDatapath(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *IGMPGroup) GetPorts() []string {
	return a.Ports
}

func copyIGMPGroupPorts(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalIGMPGroupPorts(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *IGMPGroup) DeepCopyInto(b *IGMPGroup) {
	*b = *a
	b.Chassis = copyIGMPGroupChassis(a.Chassis)
	b.Datapath = copyIGMPGroupDatapath(a.Datapath)
	b.Ports = copyIGMPGroupPorts(a.Ports)
}

func (a *IGMPGroup) DeepCopy() *IGMPGroup {
	b := new(IGMPGroup)
	a.DeepCopyInto(b)
	return b
}

func (a *IGMPGroup) CloneModelInto(b model.Model) {
	c := b.(*IGMPGroup)
	a.DeepCopyInto(c)
}

func (a *IGMPGroup) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *IGMPGroup) Equals(b *IGMPGroup) bool {
	return a.UUID == b.UUID &&
		a.Address == b.Address &&
		equalIGMPGroupChassis(a.Chassis, b.Chassis) &&
		equalIGMPGroupDatapath(a.Datapath, b.Datapath) &&
		equalIGMPGroupPorts(a.Ports, b.Ports)
}

func (a *IGMPGroup) EqualsModel(b model.Model) bool {
	c := b.(*IGMPGroup)
	return a.Equals(c)
}

var _ model.CloneableModel = &IGMPGroup{}
var _ model.ComparableModel = &IGMPGroup{}
