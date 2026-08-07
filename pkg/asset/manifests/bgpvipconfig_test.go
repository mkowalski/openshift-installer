package manifests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	mcfgv1alpha1 "github.com/openshift/api/machineconfiguration/v1alpha1"
	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/asset/installconfig"
	"github.com/openshift/installer/pkg/types"
	"github.com/openshift/installer/pkg/types/baremetal"
)

func bgpInstallConfig() *installconfig.InstallConfig {
	return installconfig.MakeAsset(&types.InstallConfig{
		Platform: types.Platform{
			BareMetal: &baremetal.Platform{
				APIVIPs:     []string{"192.168.111.5"},
				IngressVIPs: []string{"192.168.111.4"},
				BGPVIPConfig: &baremetal.BGPVIPConfig{
					LocalASN: 64512,
					Peers: []baremetal.BGPPeerConfig{
						{PeerAddress: "192.168.111.1", PeerASN: 64513},
					},
				},
				Hosts: []*baremetal.Host{
					{
						Name: "master-0",
						BGPPeers: []baremetal.BGPPeerConfig{
							{PeerAddress: "192.168.1.1", PeerASN: 64513},
						},
					},
				},
			},
		},
	})
}

func TestBGPVIPConfigFromInstallConfig(t *testing.T) {
	ic := &types.InstallConfig{Platform: types.Platform{BareMetal: &baremetal.Platform{
		APIVIPs:     []string{"192.168.111.5"},
		IngressVIPs: []string{"192.168.111.4"},
		BGPVIPConfig: &baremetal.BGPVIPConfig{
			LocalASN:    64512,
			Communities: []string{"64512:100"},
			Peers: []baremetal.BGPPeerConfig{{
				PeerAddress: "192.168.111.1", PeerASN: 64513,
				BFDEnabled: "true", EBGPMultiHop: "false",
				HoldTime: "90s", KeepaliveTime: "30s", Port: 180, Password: "s3cret",
			}},
		},
		Hosts: []*baremetal.Host{{Name: "worker-0", BGPPeers: []baremetal.BGPPeerConfig{{PeerAddress: "fd2e::1", PeerASN: 64514}}}},
	}}}
	got := bgpVIPConfigFromInstallConfig(ic)
	if got.Name != "cluster" {
		t.Fatalf("name = %q", got.Name)
	}
	assert.Equal(t, "machineconfiguration.openshift.io/v1alpha1", got.APIVersion)
	assert.Equal(t, "BGPVIPConfig", got.Kind)
	assert.Equal(t, int64(64512), got.Spec.LocalASN)
	assert.Equal(t, []string{"64512:100"}, got.Spec.Communities)
	if !assert.Len(t, got.Spec.DefaultPeers, 1) {
		return
	}
	p := got.Spec.DefaultPeers[0]
	assert.Equal(t, "192.168.111.1", p.PeerAddress)
	assert.Equal(t, int64(64513), p.PeerASN)
	assert.Equal(t, "s3cret", p.Password)
	assert.Equal(t, int32(180), p.Port)
	if p.BFD != mcfgv1alpha1.BFDModeEnabled {
		t.Errorf("bfd = %q", p.BFD)
	}
	if p.EBGPMultiHop != mcfgv1alpha1.EBGPMultiHopModeDisabled {
		t.Errorf("multihop = %q", p.EBGPMultiHop)
	}
	if p.HoldTimeSeconds != 90 || p.KeepaliveTimeSeconds != 30 {
		t.Errorf("timers = %d/%d", p.HoldTimeSeconds, p.KeepaliveTimeSeconds)
	}
	if !assert.Len(t, got.Spec.HostOverrides, 1) {
		return
	}
	if got.Spec.HostOverrides[0].Hostname != "worker-0" {
		t.Errorf("override hostname = %q", got.Spec.HostOverrides[0].Hostname)
	}
	if assert.Len(t, got.Spec.HostOverrides[0].Peers, 1) {
		assert.Equal(t, "fd2e::1", got.Spec.HostOverrides[0].Peers[0].PeerAddress)
	}
}

// Unset string flags map to omitted enums (empty string), not Disabled, and
// unset durations map to 0 — defaults come from the controller, not the
// conversion.
func TestBGPVIPConfigFromInstallConfigOmittedStaysOmitted(t *testing.T) {
	ic := &types.InstallConfig{Platform: types.Platform{BareMetal: &baremetal.Platform{
		BGPVIPConfig: &baremetal.BGPVIPConfig{
			LocalASN: 64512,
			Peers: []baremetal.BGPPeerConfig{{
				PeerAddress: "192.168.111.1", PeerASN: 64513,
				BFDEnabled: "", EBGPMultiHop: "",
			}},
		},
	}}}
	got := bgpVIPConfigFromInstallConfig(ic)
	p := got.Spec.DefaultPeers[0]
	assert.Equal(t, mcfgv1alpha1.BFDMode(""), p.BFD)
	assert.Equal(t, mcfgv1alpha1.EBGPMultiHopMode(""), p.EBGPMultiHop)
	assert.Equal(t, int32(0), p.HoldTimeSeconds)
	assert.Equal(t, int32(0), p.KeepaliveTimeSeconds)
	assert.Empty(t, got.Spec.HostOverrides)
}

// The asset must render a BGPVIPConfig CR manifest (not a ConfigMap).
func TestBGPVIPConfigAssetRendersCR(t *testing.T) {
	parents := asset.Parents{}
	parents.Add(bgpInstallConfig())

	a := &BGPVIPConfigMap{}
	if !assert.NoError(t, a.Generate(context.Background(), parents)) {
		return
	}
	files := a.Files()
	if !assert.Len(t, files, 1) {
		return
	}
	data := string(files[0].Data)
	assert.Contains(t, data, "kind: BGPVIPConfig")
	assert.Contains(t, data, "apiVersion: machineconfiguration.openshift.io/v1alpha1")
	assert.Contains(t, data, "name: cluster")
	assert.NotContains(t, data, "kind: ConfigMap")
	assert.NotContains(t, data, "apiVIPs")
	assert.NotContains(t, data, "ingressVIPs")
}
