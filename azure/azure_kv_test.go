package azure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unsetAzureEnv(t *testing.T) {
	for _, env := range []string{AzureTenantID, AzureClientID, AzureClientSecret,
		AzureClientCertPath, AzureClientCertPassword, AzureEnviornment, AzureVaultURL} {
		t.Setenv(env, "")
	}
}

func testConfig() map[string]interface{} {
	return map[string]interface{}{
		AzureTenantID: "test-tenant-id",
		AzureClientID: "test-client-id",
		AzureVaultURL: "https://test-vault.vault.azure.net/",
	}
}

// createCert writes a self-signed cert and its RSA key to a PEM file.
func createCert(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)

	path := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func TestNew(t *testing.T) {
	unsetAzureEnv(t)

	_, err := New(nil)
	assert.Equal(t, ErrAzureTenantIDNotSet, err)
	t.Setenv(AzureTenantID, "test-tenant-id")

	_, err = New(nil)
	assert.Equal(t, ErrAzureClientIDNotSet, err)
	t.Setenv(AzureClientID, "test-client-id")

	_, err = New(nil)
	assert.Equal(t, ErrAzureVaultURLNotSet, err)
	t.Setenv(AzureVaultURL, "https://test-vault.vault.azure.net/")

	_, err = New(nil)
	assert.Equal(t, ErrAzureAuthMethodNotSet, err)
	t.Setenv(AzureClientSecret, "test-secret")

	_, err = New(nil)
	assert.NoError(t, err)
}

func TestNewWithClientSecret(t *testing.T) {
	unsetAzureEnv(t)

	config := testConfig()
	config[AzureClientSecret] = "test-secret"
	_, err := New(config)
	assert.NoError(t, err)

	config[AzureTenantID] = "invalid_tenant_id"
	_, err = New(config)
	assert.Error(t, err)
}

func TestNewWithClientCert(t *testing.T) {
	unsetAzureEnv(t)

	config := testConfig()
	config[AzureClientCertPath] = createCert(t)
	_, err := New(config)
	assert.NoError(t, err)

	config[AzureClientCertPath] = "/does/not/exist.pem"
	_, err = New(config)
	assert.Error(t, err)

	badCert := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(badCert, []byte("not a cert"), 0600))
	config[AzureClientCertPath] = badCert
	_, err = New(config)
	assert.Error(t, err)

	// client secret is used when both are set
	config[AzureClientSecret] = "test-secret"
	_, err = New(config)
	assert.NoError(t, err)
}

func TestGetAzureClientOptions(t *testing.T) {
	unsetAzureEnv(t)

	clouds := map[string]cloud.Configuration{
		"":                       cloud.AzurePublic,
		"AzureCloud":             cloud.AzurePublic,
		"AzurePublicCloud":       cloud.AzurePublic,
		"azurepubliccloud":       cloud.AzurePublic,
		"AzureUSGovernment":      cloud.AzureGovernment,
		"AzureUSGovernmentCloud": cloud.AzureGovernment,
		"AzureChinaCloud":        cloud.AzureChina,
	}
	for env, want := range clouds {
		opts, err := getAzureClientOptions(map[string]interface{}{AzureEnviornment: env})
		assert.NoError(t, err, env)
		assert.Equal(t, want, opts.Cloud, env)
	}

	_, err := getAzureClientOptions(map[string]interface{}{AzureEnviornment: "AzureGermanCloud"})
	assert.Equal(t, ErrAzureGermanCloudDeprecated, err)

	_, err = getAzureClientOptions(map[string]interface{}{AzureEnviornment: "foo"})
	assert.Equal(t, ErrAzureInvalidCloudEnv, err)
}
