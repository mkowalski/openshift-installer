package manifests

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

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
	got, secrets := bgpVIPConfigFromInstallConfig(ic)
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
	assert.Equal(t, "bgp-vip-peer-192-168-111-1", p.PasswordSecret.Name)
	if assert.Len(t, secrets, 1) {
		s := secrets[0]
		assert.Equal(t, "bgp-vip-peer-192-168-111-1", s.Name)
		assert.Equal(t, "openshift-config", s.Namespace)
		assert.Equal(t, corev1.SecretTypeBasicAuth, s.Type)
		assert.Equal(t, []byte("s3cret"), s.Data["password"])
	}
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
		assert.Empty(t, got.Spec.HostOverrides[0].Peers[0].PasswordSecret.Name)
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
	got, secrets := bgpVIPConfigFromInstallConfig(ic)
	p := got.Spec.DefaultPeers[0]
	assert.Equal(t, mcfgv1alpha1.BFDMode(""), p.BFD)
	assert.Equal(t, mcfgv1alpha1.EBGPMultiHopMode(""), p.EBGPMultiHop)
	assert.Equal(t, int32(0), p.HoldTimeSeconds)
	assert.Equal(t, int32(0), p.KeepaliveTimeSeconds)
	assert.Equal(t, mcfgv1alpha1.BGPVIPPasswordSecret{}, p.PasswordSecret)
	assert.Empty(t, secrets)
	assert.Empty(t, got.Spec.HostOverrides)
}

func TestBGPSanitizeNameComponent(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.111.1", "192-168-111-1"},
		{"fd2e::1", "fd2e-1"},
		{"fd2e:6f44:5dd8::1", "fd2e-6f44-5dd8-1"},
		{"::1", "1"},
		{"2001:db8::", "2001-db8"},
		{"Master-0.Example.COM", "master-0-example-com"},
		{"worker--0", "worker-0"},
		{"-host-", "host"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, bgpSanitizeNameComponent(c.in), "input %q", c.in)
	}
}

func TestBGPPeerSecretName(t *testing.T) {
	assert.Equal(t, "bgp-vip-peer-192-168-111-1", bgpPeerSecretName("", "192.168.111.1"))
	assert.Equal(t, "bgp-vip-peer-master-0-fd2e-1", bgpPeerSecretName("master-0", "fd2e::1"))
}

// Peers with passwords in hostOverrides get hostname-scoped secret names.
func TestBGPVIPConfigOverridePeerSecretNaming(t *testing.T) {
	ic := &types.InstallConfig{Platform: types.Platform{BareMetal: &baremetal.Platform{
		BGPVIPConfig: &baremetal.BGPVIPConfig{LocalASN: 64512},
		Hosts: []*baremetal.Host{{Name: "Worker-0", BGPPeers: []baremetal.BGPPeerConfig{
			{PeerAddress: "fd2e::1", PeerASN: 64514, Password: "hunter2"},
		}}},
	}}}
	got, secrets := bgpVIPConfigFromInstallConfig(ic)
	if assert.Len(t, secrets, 1) {
		assert.Equal(t, "bgp-vip-peer-worker-0-fd2e-1", secrets[0].Name)
	}
	assert.Equal(t, "bgp-vip-peer-worker-0-fd2e-1", got.Spec.HostOverrides[0].Peers[0].PasswordSecret.Name)
}

// The asset must render a BGPVIPConfig CR manifest (not a ConfigMap).
// Peers without passwords produce no Secret files, and passwordSecret is
// omitted from the serialized CR (omitzero).
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
	assert.NotContains(t, data, "passwordSecret")
	assert.NotContains(t, data, "password")
}

// Peers with install-config passwords must produce basic-auth Secret
// manifests referenced by name in the CR, with no plaintext in the CR.
func TestBGPVIPConfigAssetRendersPeerSecrets(t *testing.T) {
	ic := installconfig.MakeAsset(&types.InstallConfig{
		Platform: types.Platform{
			BareMetal: &baremetal.Platform{
				BGPVIPConfig: &baremetal.BGPVIPConfig{
					LocalASN: 64512,
					Peers: []baremetal.BGPPeerConfig{
						{PeerAddress: "192.168.111.1", PeerASN: 64513, Password: "s3cret"},
					},
				},
				Hosts: []*baremetal.Host{{
					Name: "master-0",
					BGPPeers: []baremetal.BGPPeerConfig{
						{PeerAddress: "fd2e::1", PeerASN: 64514, Password: "hunter2"},
					},
				}},
			},
		},
	})
	parents := asset.Parents{}
	parents.Add(ic)

	a := &BGPVIPConfigMap{}
	if !assert.NoError(t, a.Generate(context.Background(), parents)) {
		return
	}
	files := a.Files()
	if !assert.Len(t, files, 3) {
		return
	}
	byName := map[string]string{}
	for _, f := range files {
		byName[f.Filename] = string(f.Data)
	}

	cr := byName["manifests/bgp-vip-config.yaml"]
	if !assert.NotEmpty(t, cr) {
		return
	}
	assert.Contains(t, cr, "passwordSecret:")
	assert.Contains(t, cr, "name: bgp-vip-peer-192-168-111-1")
	assert.Contains(t, cr, "name: bgp-vip-peer-master-0-fd2e-1")
	assert.NotContains(t, cr, "s3cret")
	assert.NotContains(t, cr, "hunter2")

	defSecret := byName["openshift/bgp-vip-peer-secret-bgp-vip-peer-192-168-111-1.yaml"]
	if assert.NotEmpty(t, defSecret, "default peer secret file missing; files: %v", byName) {
		assert.Contains(t, defSecret, "kind: Secret")
		assert.Contains(t, defSecret, "apiVersion: v1")
		assert.Contains(t, defSecret, "type: kubernetes.io/basic-auth")
		assert.Contains(t, defSecret, "namespace: openshift-config")
		assert.Contains(t, defSecret, "name: bgp-vip-peer-192-168-111-1")
		assert.Contains(t, defSecret, base64.StdEncoding.EncodeToString([]byte("s3cret")))
	}

	ovrSecret := byName["openshift/bgp-vip-peer-secret-bgp-vip-peer-master-0-fd2e-1.yaml"]
	if assert.NotEmpty(t, ovrSecret, "override peer secret file missing; files: %v", byName) {
		assert.Contains(t, ovrSecret, "name: bgp-vip-peer-master-0-fd2e-1")
		assert.Contains(t, ovrSecret, "type: kubernetes.io/basic-auth")
		assert.Contains(t, ovrSecret, base64.StdEncoding.EncodeToString([]byte("hunter2")))
	}
}
