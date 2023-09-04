package auth

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/fluxcd/pkg/oci/auth/azure"
	"github.com/fluxcd/pkg/oci/auth/login"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	soci "github.com/fluxcd/source-controller/internal/oci"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

func GetManagerOptsFromSA(ctx context.Context, client ctrlClient.Client, provider string, saNsName types.NamespacedName) (soci.ManagerOptFunc, error) {
	switch provider {
	case sourcev1.AzureOCIProvider:
		return getAzureLoginOpts(ctx, client, saNsName)
	default:
		return nil, fmt.Errorf("authenticating with service account not support for '%s' provider", provider)
	}
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
