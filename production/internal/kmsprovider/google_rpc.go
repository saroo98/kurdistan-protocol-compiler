// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package kmsprovider

import (
	"context"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

type GoogleRPC struct{ client *kms.KeyManagementClient }

func NewGoogleRPC(client *kms.KeyManagementClient) (*GoogleRPC, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	return &GoogleRPC{client: client}, nil
}

func (rpc *GoogleRPC) GetCryptoKey(ctx context.Context, name string) (*kmspb.CryptoKey, error) {
	return rpc.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
}

func (rpc *GoogleRPC) GetCryptoKeyVersion(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	return rpc.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
}

func (rpc *GoogleRPC) GetPublicKey(ctx context.Context, name string) (*kmspb.PublicKey, error) {
	return rpc.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
}

func (rpc *GoogleRPC) AsymmetricSign(ctx context.Context, request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return rpc.client.AsymmetricSign(ctx, request)
}

var _ RPC = (*GoogleRPC)(nil)
