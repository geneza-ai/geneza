package controller

import "testing"

func TestRelaySecretsSynthDefault(t *testing.T) {
	c := &Config{RelaySharedSecret: "topsecret"}
	c.applyDefaults()
	sec, ok := c.RelaySecrets["default"]
	if !ok || sec.Current != "topsecret" {
		t.Fatalf("synthesized secrets = %+v ok=%v (want default/topsecret)", sec, ok)
	}
}

func TestRelaySecretsSynthUsesRegion(t *testing.T) {
	c := &Config{RelaySharedSecret: "s", Region: "eu"}
	c.applyDefaults()
	if c.RelaySecrets["eu"].Current != "s" {
		t.Fatalf("region synth = %+v, want eu->s", c.RelaySecrets)
	}
	if _, ok := c.RelaySecrets["default"]; ok {
		t.Fatal("a region controller must not synthesize into the default region")
	}
}

func TestRelaySecretsExplicitMapWins(t *testing.T) {
	c := &Config{RelaySharedSecret: "flat", RelaySecrets: map[string]RegionSecret{"eu": {Current: "explicit"}}}
	c.applyDefaults()
	if _, ok := c.RelaySecrets["default"]; ok {
		t.Fatal("an explicit relay_secrets map must not be overwritten by the flat-secret synth")
	}
	if c.RelaySecrets["eu"].Current != "explicit" {
		t.Fatalf("explicit secrets clobbered: %+v", c.RelaySecrets["eu"])
	}
}
