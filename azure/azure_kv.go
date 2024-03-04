package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/libopenstorage/secrets"
	"github.com/portworx/sched-ops/task"
)

const (
	Name       = secrets.TypeAzure
	AzureCloud = "AzurePublicCloud"
	// AzureTenantID for Azure Active Directory
	AzureTenantID = "AZURE_TENANT_ID"
	// AzureClientID of service principal account
	AzureClientID = "AZURE_CLIENT_ID"
	// AzureClientSecret of service principal account
	AzureClientSecret = "AZURE_CLIENT_SECRET"
	// AzureClientCertPath is path of the client certificate
	AzureClientCertPath = "AZURE_CLIENT_CERT_PATH"
	// AzureClientCertPassword is the password of the private key
	AzureClientCertPassword = "AZURE_CIENT_CERT_PASSWORD"
	// AzureEnviornment to connect
	AzureEnviornment = "AZURE_ENVIRONMENT"
	// AzureVaultURI of azure key vault
	AzureVaultURL = "AZURE_VAULT_URL"
	// Default context timeout for Azure SDK API's
	defaultTimeout = 30 * time.Second
	// timeout
	timeout = 8 * time.Second
	// retrytimeout
	retryTimeout = 4 * time.Second
)

var (
	ErrAzureTenantIDNotSet    = errors.New("AZURE_TENANT_ID not set.")
	ErrAzureClientIDNotSet    = errors.New("AZURE_CLIENT_ID not set.")
	ErrAzureSecretIDNotSet    = errors.New("AZURE_SECRET_ID not set.")
	ErrAzureAuthMedhodNotSet  = errors.New("AZURE_SECRET_ID or AZURE_CLIENT_CERT_PATH not set")
	ErrAzureVaultURLNotSet    = errors.New("AZURE_VAULT_URL not set.")
	ErrAzureEnvironmentNotset = errors.New("AZURE_ENVIRONMENT not set.")
	ErrAzureConfigMissing     = errors.New("AzureConfig is not provided")
	ErrAzureAuthentication    = errors.New("Azure authentication failed")
	ErrInvalidSecretResp      = errors.New("Secret Data received from secrets provider is either empty/invalid")
)

type azureSecrets struct {
	kv      azsecrets.Client
	baseURL string
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {

	tenantID := getAzureKVParams(secretConfig, AzureTenantID)
	if tenantID == "" {
		return nil, ErrAzureTenantIDNotSet
	}
	clientID := getAzureKVParams(secretConfig, AzureClientID)
	if clientID == "" {
		return nil, ErrAzureClientIDNotSet
	}
	secretID := getAzureKVParams(secretConfig, AzureClientSecret)
	clientCertPath := getAzureKVParams(secretConfig, AzureClientCertPath)
	clientCertPassword := getAzureKVParams(secretConfig, AzureClientCertPassword)

	envName := getAzureKVParams(secretConfig, AzureEnviornment)
	if envName == "" {
		// we set back to default AzurePublicCloud
		envName = AzureCloud
	}
	vaultURL := getAzureKVParams(secretConfig, AzureVaultURL)
	if vaultURL == "" {
		return nil, ErrAzureVaultURLNotSet
	}

	var client *azsecrets.Client
	var err error
	if secretID != "" {
		client, err = getAzureVaultClient(clientID, secretID, tenantID, vaultURL)
		if err != nil {
			return nil, err
		}
	} else if clientCertPath != "" {
		client, err = getAzureVaultClientWithCert(clientID, tenantID, vaultURL, clientCertPath, clientCertPassword)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ErrAzureAuthMedhodNotSet
	}

	return &azureSecrets{
		kv:      *client,
		baseURL: vaultURL,
	}, nil
}

func (az *azureSecrets) GetSecret(
	secretID string,
	keyContext map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if secretID == "" {
		return nil, secrets.NoVersion, secrets.ErrEmptySecretId
	}

	t := func() (interface{}, bool, error) {
		// passing empty version to always get the latest version of the secret.
		secretResp, err := az.kv.GetSecret(ctx, secretID, "", nil)
		if err != nil {
			if strings.Contains(err.Error(), "SecretNotFound") {
				return nil, false, secrets.ErrSecretNotFound
			}
			return nil, true, err
		}
		return secretResp, false, nil
	}
	resp, err := task.DoRetryWithTimeout(t, timeout, retryTimeout)
	if err != nil {
		return nil, secrets.NoVersion, err
	}

	fmt.Printf("SP - resp 1 - %+v\n", resp)
	fmt.Printf("SP - resp 2 - %T\n", resp)
	secretResp, ok := resp.(azsecrets.GetSecretResponse)
	fmt.Printf("SP - resp - %+v\n", secretResp)
	fmt.Printf("SP - ok or not - %+v\n", ok)
	if !ok || secretResp.Value == nil {
		return nil, secrets.NoVersion, ErrInvalidSecretResp
	}
	secretData := make(map[string]interface{})
	err = json.Unmarshal([]byte(*secretResp.Value), &secretData)
	if err != nil {
		secretData = make(map[string]interface{})
		secretData[secretID] = *secretResp.Value
	}

	// TODO: Azure does not support version numbers, but we could leverage LastUpdateTime as an indicator
	// for changes in azure secret version if there is a need.
	return secretData, secrets.NoVersion, nil
}

func (az *azureSecrets) PutSecret(
	secretName string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var secretResp azsecrets.SecretBundle
	if secretName == "" {
		return secrets.NoVersion, secrets.ErrEmptySecretId
	}
	if len(secretData) == 0 {
		return secrets.NoVersion, secrets.ErrEmptySecretData
	}

	value, err := json.Marshal(secretData)
	if err != nil {
		return secrets.NoVersion, err
	}

	valueStr := string(value)
	t := func() (interface{}, bool, error) {
		params := azsecrets.SetSecretParameters{Value: &valueStr}
		az.kv.SetSecret(ctx, secretName, params, nil)
		if err != nil {
			return nil, true, err
		}
		return secretResp, false, nil
	}
	_, err = task.DoRetryWithTimeout(t, timeout, retryTimeout)

	return secrets.NoVersion, err
}
func (az *azureSecrets) DeleteSecret(
	secretName string,
	keyContext map[string]string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if secretName == "" {
		return secrets.ErrEmptySecretId
	}
	_, err := az.kv.DeleteSecret(ctx, secretName, nil)

	return err
}

func (az *azureSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func (az *azureSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) String() string {
	return Name
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
