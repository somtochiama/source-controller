package auth

import (
	"bytes"
	"cloud.google.com/go/compute/metadata"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/oci/auth/azure"
	"github.com/fluxcd/pkg/oci/auth/gcp"
	"github.com/fluxcd/pkg/oci/auth/login"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	soci "github.com/fluxcd/source-controller/internal/oci"
)

func GetManagerOptsFromSA(ctx context.Context, client ctrlClient.Client, provider string, saNsName types.NamespacedName) (soci.ManagerOptFunc, error) {
	switch provider {
	case sourcev1.AzureOCIProvider:
		return getAzureLoginOpts(ctx, client, saNsName)
	case sourcev1.GoogleOCIProvider:
		return getGCPLoginOpts(ctx, client, saNsName)
	default:
		return nil, fmt.Errorf("authenticating with service account not support for '%s' provider", provider)
	}
}

func getGCPLoginOpts(ctx context.Context, client ctrlClient.Client, nsName types.NamespacedName) (soci.ManagerOptFunc, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: nsName.Name, Namespace: nsName.Namespace},
	}
	if err := client.Get(ctx, types.NamespacedName{Namespace: sa.Namespace, Name: sa.Name}, sa); err != nil {
		return nil, err
	}

	gcpSAName := sa.Annotations["iam.gke.io/gcp-service-account"]
	if gcpSAName == "" {
		return nil, fmt.Errorf("no `iam.gke.io/gcp-service-account` annotation on serviceaccount")
	}

	// exchange oidc token for identity binding token
	idPool, idProvider, err := getDetailsFromMetadataService()
	if err != nil {
		return nil, err
	}

	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{idPool},
		},
	}
	if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
		return nil, err
	}

	accessToken, err := tradeIDBindToken(ctx, tr.Status.Token, idPool, idProvider)
	if err != nil {
		return nil, fmt.Errorf("error exchanging token: '%s'", err)
	}
	// exchange identity binding token for iam token
	iamClient, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating iam client: '%s'", err)
	}

	saResponse, err := iamClient.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name: fmt.Sprintf("projects/-/serviceAccounts/%s", gcpSAName),
		Scope: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
	}, gax.WithGRPCOptions(grpc.PerRPCCredentials(oauth.TokenSource{TokenSource: oauth2.StaticTokenSource(accessToken)})))

	if err != nil {
		return nil, fmt.Errorf("error exchanging access token w gcp iam: '%w'", err)
	}

	managerOpt := func(m *login.Manager) {
		gcpClient := gcp.NewClient()
		gcpClient.WithAccessToken(saResponse.GetAccessToken())
		m.WithGCRClient(gcpClient)
	}

	return managerOpt, nil
}

func getDetailsFromMetadataService() (string, string, error) {
	projectID, err := metadata.ProjectID()
	if err != nil {
		return "", "", fmt.Errorf("unable to get project id from metadata server: '%s'", err)
	}

	location, err := metadata.InstanceAttributeValue("cluster-location")
	if err != nil {
		return "", "", fmt.Errorf("unable to get cluster location from metadata server: '%s'", err)
	}

	clusterName, err := metadata.InstanceAttributeValue("cluster-name")
	if err != nil {
		return "", "", fmt.Errorf("unable to get cluster name from metadata server: '%s'", err)
	}

	idProvider := fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
		projectID, location, clusterName)

	idPool := fmt.Sprintf("%s.svc.id.goog", projectID)
	return idPool, idProvider, nil
}

func getAzureLoginOpts(ctx context.Context, client ctrlClient.Client, nsName types.NamespacedName) (soci.ManagerOptFunc, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: nsName.Name, Namespace: nsName.Namespace},
	}
	if err := client.Get(ctx, types.NamespacedName{Namespace: sa.Namespace, Name: sa.Name}, sa); err != nil {
		return nil, err
	}

	clientID := sa.Annotations["azure.workload.identity/client-id"]
	if clientID == "" {
		return nil, fmt.Errorf("no client id annotation on serviceaccount")
	}
	tenantID := sa.Annotations["azure.workload.identity/tenant-id"]
	if tenantID == "" {
		return nil, fmt.Errorf("no tenamt id annotation on serviceaccount")
	}

	getAssertionToken := func(ctx context.Context) (string, error) {
		tr := &authenticationv1.TokenRequest{}
		if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
			return "", err
		}

		return tr.Status.Token, nil
	}

	clientCred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, getAssertionToken, nil)
	if err != nil {
		return nil, err
	}

	managerOpt := func(m *login.Manager) {
		acrClient := azure.NewClient()
		acrClient.WithTokenCredential(clientCred)
		m.WithACRClient(acrClient)
	}

	return managerOpt, nil
}

// Copied from: https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/blob/053d18c0a8fe522d5acea547b22b97a04ac7134d/auth/auth.go#L269C1-L307C2
func tradeIDBindToken(ctx context.Context, k8sToken, idPool, idProvider string) (*oauth2.Token, error) {
	fmt.Println(k8sToken)
	body, err := json.Marshal(map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"subject_token":        k8sToken,
		"audience":             fmt.Sprintf("identitynamespace:%s:%s", idPool, idProvider),
		"scope":                "https://www.googleapis.com/auth/cloud-platform",
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://securetoken.googleapis.com/v1/identitybindingtoken", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get idbindtoken token, status: %v", resp.StatusCode)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	idBindToken := &oauth2.Token{}
	if err := json.Unmarshal(respBody, idBindToken); err != nil {
		return nil, err
	}
	return idBindToken, nil
}
