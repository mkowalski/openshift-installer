package manifests

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	mcfgv1alpha1 "github.com/openshift/api/machineconfiguration/v1alpha1"
	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/asset/installconfig"
	"github.com/openshift/installer/pkg/types"
	"github.com/openshift/installer/pkg/types/baremetal"
)

var (
	bgpVIPConfigMapFileName = path.Join(manifestDir, "bgp-vip-config.yaml")

	bgpNameSanitizeRE = regexp.MustCompile(`[:.]+`)
	bgpNameSqueezeRE  = regexp.MustCompile(`-+`)
)

// bgpSanitizeNameComponent turns an address or hostname into an RFC 1123
// label fragment: lowercase, ':' and '.' replaced by '-', repeated '-'
// squeezed, leading/trailing '-' trimmed.
func bgpSanitizeNameComponent(s string) string {
	s = strings.ToLower(s)
	s = bgpNameSanitizeRE.ReplaceAllString(s, "-")
	s = bgpNameSqueezeRE.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// bgpPeerSecretName returns the deterministic Secret name for a peer's BGP
// password. hostname is empty for default peers.
func bgpPeerSecretName(hostname, address string) string {
	if hostname == "" {
		return fmt.Sprintf("bgp-vip-peer-%s", bgpSanitizeNameComponent(address))
	}
	return fmt.Sprintf("bgp-vip-peer-%s-%s", bgpSanitizeNameComponent(hostname), bgpSanitizeNameComponent(address))
}

// bgpPeerPasswordSecret builds the kubernetes.io/basic-auth Secret carrying
// the peer's BGP password in the openshift-config namespace.
func bgpPeerPasswordSecret(name, password string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-config",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"password": []byte(password),
		},
	}
}

// bgpBoolFlagToBFDMode converts the install-config string flag ("true",
// "false" or "") to the CRD enum. An empty value stays empty: defaults are
// applied by the consuming controllers, not by this conversion.
func bgpBoolFlagToBFDMode(v string) mcfgv1alpha1.BFDMode {
	switch v {
	case "true":
		return mcfgv1alpha1.BFDModeEnabled
	case "false":
		return mcfgv1alpha1.BFDModeDisabled
	}
	return ""
}

// bgpBoolFlagToEBGPMultiHopMode converts the install-config string flag
// ("true", "false" or "") to the CRD enum, keeping empty values empty.
func bgpBoolFlagToEBGPMultiHopMode(v string) mcfgv1alpha1.EBGPMultiHopMode {
	switch v {
	case "true":
		return mcfgv1alpha1.EBGPMultiHopModeEnabled
	case "false":
		return mcfgv1alpha1.EBGPMultiHopModeDisabled
	}
	return ""
}

// bgpDurationToSeconds converts an install-config duration string (e.g.
// "90s") to whole seconds. Empty or unparsable values map to 0 (omitted).
func bgpDurationToSeconds(v string) int32 {
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return int32(d.Seconds())
}

func bgpPeerToCR(p baremetal.BGPPeerConfig, hostname string, secrets *[]*corev1.Secret) mcfgv1alpha1.BGPVIPPeer {
	peer := mcfgv1alpha1.BGPVIPPeer{
		PeerAddress:          p.PeerAddress,
		PeerASN:              p.PeerASN,
		Port:                 p.Port,
		BFD:                  bgpBoolFlagToBFDMode(p.BFDEnabled),
		EBGPMultiHop:         bgpBoolFlagToEBGPMultiHopMode(p.EBGPMultiHop),
		HoldTimeSeconds:      bgpDurationToSeconds(p.HoldTime),
		KeepaliveTimeSeconds: bgpDurationToSeconds(p.KeepaliveTime),
	}
	if p.Password != "" {
		name := bgpPeerSecretName(hostname, p.PeerAddress)
		peer.PasswordSecret = mcfgv1alpha1.BGPVIPPasswordSecret{Name: name}
		*secrets = append(*secrets, bgpPeerPasswordSecret(name, p.Password))
	}
	return peer
}

// bgpVIPConfigFromInstallConfig converts the baremetal platform's
// BGPVIPConfig install-config section into the machineconfiguration
// BGPVIPConfig singleton CR named "cluster", plus the peer password
// Secrets referenced by it. apiVIPs/ingressVIPs are not part of the CR and
// are intentionally dropped. Install-config inline peer passwords are moved
// into kubernetes.io/basic-auth Secrets in the openshift-config namespace;
// the CR carries only the reference.
func bgpVIPConfigFromInstallConfig(ic *types.InstallConfig) (*mcfgv1alpha1.BGPVIPConfig, []*corev1.Secret) {
	bm := ic.Platform.BareMetal
	bgpConfig := bm.BGPVIPConfig
	var secrets []*corev1.Secret

	cr := &mcfgv1alpha1.BGPVIPConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: mcfgv1alpha1.GroupVersion.String(),
			Kind:       "BGPVIPConfig",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: mcfgv1alpha1.BGPVIPConfigSpec{
			LocalASN:    bgpConfig.LocalASN,
			Communities: bgpConfig.Communities,
		},
	}

	for _, p := range bgpConfig.Peers {
		cr.Spec.DefaultPeers = append(cr.Spec.DefaultPeers, bgpPeerToCR(p, "", &secrets))
	}

	for _, host := range bm.Hosts {
		if host == nil || len(host.BGPPeers) == 0 {
			continue
		}
		override := mcfgv1alpha1.BGPVIPHostPeers{Hostname: host.Name}
		for _, p := range host.BGPPeers {
			override.Peers = append(override.Peers, bgpPeerToCR(p, host.Name, &secrets))
		}
		cr.Spec.HostOverrides = append(cr.Spec.HostOverrides, override)
	}

	return cr, secrets
}

// BGPVIPConfigMap generates the BGPVIPConfig custom resource manifest for
// the BGP VIP feature, along with peer password Secret manifests.
type BGPVIPConfigMap struct {
	Config   *mcfgv1alpha1.BGPVIPConfig
	FileList []*asset.File
}

var _ asset.WritableAsset = (*BGPVIPConfigMap)(nil)

// Name returns a human friendly name for the asset.
func (*BGPVIPConfigMap) Name() string {
	return "BGP VIP Config ConfigMap"
}

// Dependencies returns all of the dependencies directly needed to generate
// the asset.
func (*BGPVIPConfigMap) Dependencies() []asset.Asset {
	return []asset.Asset{
		&installconfig.InstallConfig{},
	}
}

// Generate generates the BGPVIPConfig custom resource manifest.
func (b *BGPVIPConfigMap) Generate(_ context.Context, dependencies asset.Parents) error {
	installConfig := &installconfig.InstallConfig{}
	dependencies.Get(installConfig)

	// Only generate for baremetal platform with BGPVIPConfig set.
	if installConfig.Config.Platform.Name() != baremetal.Name ||
		installConfig.Config.Platform.BareMetal == nil ||
		installConfig.Config.Platform.BareMetal.BGPVIPConfig == nil {
		return nil
	}

	cr, secrets := bgpVIPConfigFromInstallConfig(installConfig.Config)

	crData, err := yaml.Marshal(cr)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s manifest", b.Name())
	}
	b.Config = cr
	b.FileList = []*asset.File{{
		Filename: bgpVIPConfigMapFileName,
		Data:     crData,
	}}
	for _, secret := range secrets {
		secretData, err := yaml.Marshal(secret)
		if err != nil {
			return errors.Wrapf(err, "failed to create %s peer password secret manifest", b.Name())
		}
		b.FileList = append(b.FileList, &asset.File{
			Filename: path.Join(openshiftManifestDir, fmt.Sprintf("bgp-vip-peer-secret-%s.yaml", secret.Name)),
			Data:     secretData,
		})
	}
	asset.SortFiles(b.FileList)
	return nil
}

// Files returns the files generated by the asset.
func (b *BGPVIPConfigMap) Files() []*asset.File {
	return b.FileList
}

// Load loads the already-rendered files back from disk.
func (b *BGPVIPConfigMap) Load(f asset.FileFetcher) (bool, error) {
	return false, nil
}
