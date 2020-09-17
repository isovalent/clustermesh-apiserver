// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"net"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
        "github.com/cilium/cilium/pkg/source"

        "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VMManager struct {
	ciliumClient      clientset.Interface
	identityAllocator *identityCache.CachingIdentityAllocator
}

func NewVMManager(ciliumK8sClient clientset.Interface) *VMManager {
	m := &VMManager{
		ciliumClient: ciliumK8sClient,
	}
	m.identityAllocator = identityCache.NewCachingIdentityAllocator(m)

	if option.Config.EnableWellKnownIdentities {
		identity.InitWellKnownIdentities(option.Config)
	}
	m.identityAllocator.InitIdentityAllocator(ciliumK8sClient, identityStore)
	return m
}

//
// IdentityAllocatorOwner interface
//

// UpdateIdentities will be called when identities have changed
func (m *VMManager) UpdateIdentities(added, deleted identityCache.IdentityCache) {}

// GetSuffix must return the node specific suffix to use
func (m *VMManager) GetNodeSuffix() string {
	return "vm-allocator"
}

//
// Observer interface
//

func (m *VMManager) OnUpdate(k store.Key) {
	if n, ok := k.(*nodeTypes.Node); ok {
		if n.Source == source.Local {
			log.Info("VM Cilium Node updated: %v", n)
			m.UpdateCiliumNodeResource(n)
			m.RegisterVMEndpoint(n)
		}
	}
}

func (m *VMManager) OnDelete(k store.NamedKey) {
	if n, ok := k.(*nodeTypes.Node); ok {
		if n.Source == source.Local {
			log.Info("VM Cilium Node deleted: %v", n)
		}
	}
}

func (m *VMManager) RegisterVMEndpoint(node *nodeTypes.Node) {
	namespace := "default"
	account := "default"

	labelMap := map[string]string{
		"name": node.Name,
		"io.cilium.k8s.policy.cluster": clusterName,
		"io.kubernetes.pod.namespace": namespace,
		"io.cilium.k8s.policy.serviceaccount": account,
	}
	for k, v := range node.Labels {
		labelMap[k] = v
	}
	vmLabels := labels.Map2Labels(labelMap, "k8s")

	log.Debug("Resolving identity for VM labels")
	allocateCtx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	// XXX: Allocate only if not already allocated
	allocatedIdentity, allocated, err := m.identityAllocator.AllocateIdentity(allocateCtx, vmLabels, true)
	if err != nil {
		log.WithError(err).Error("unable to resolve identity")
	} else {
		if allocated {
			log.Infof("Allocated identity %v", allocatedIdentity)
		} else {
			log.Infof("Identity %v was already allocated", allocatedIdentity)
		}
		var addresses []*ciliumv2.AddressPair
		i := 0
		for _, addr := range node.IPAddresses {
			if len(addresses) == i {
				addresses = append(addresses, &ciliumv2.AddressPair{})
			}
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				if addresses[i].IPV4 != "" {
					addresses = append(addresses, &ciliumv2.AddressPair{})
					i++
				}
				addresses[i].IPV4 = ipv4.String()
			} else if ipv6 := addr.IP.To16(); ipv6 != nil {
				if addresses[i].IPV6 != "" {
					addresses = append(addresses, &ciliumv2.AddressPair{})
					i++
				}
				addresses[i].IPV6 = ipv6.String()
			}
		}
		m.UpdateCiliumEndpointResource(node.Name, namespace, allocatedIdentity, addresses, node.GetNodeIP(false))
	}
}

const (
        maxRetryCount = 5
)

// UpdateCiliumNodeResource updates the CiliumNode resource representing the
// local node
func (m *VMManager) UpdateCiliumNodeResource(node *nodeTypes.Node) {
	nr := node.ToCiliumNode()

        for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		log.Info("Getting CN during an update")
                nodeResource, err := m.ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), node.Name, metav1.GetOptions{})
                if err != nil {
                        if _, err = m.ciliumClient.CiliumV2().CiliumNodes().Create(context.TODO(), nr, metav1.CreateOptions{}); err != nil {
                                if errors.IsConflict(err) {
                                        log.WithError(err).Warn("Unable to create CiliumNode resource, will retry")
                                        continue
                                }
                                log.WithError(err).Fatal("Unable to create CiliumNode resource")
                        } else {
                                log.Info("Successfully created CiliumNode resource: %v", *nr)
                                return
                        }

                } else {
			nodeResource.ObjectMeta.Labels = nr.ObjectMeta.Labels
			nodeResource.Spec = nr.Spec
                        if _, err := m.ciliumClient.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{}); err != nil {
                                if errors.IsConflict(err) {
                                        log.WithError(err).Warn("Unable to update CiliumNode resource, will retry")
                                        continue
                                }
                                log.WithError(err).Fatal("Unable to update CiliumNode resource")
                        } else {
                                log.Info("Successfully updated CiliumNode resource: %v", *nodeResource)
                                return
                        }
                }
        }
        log.Fatal("Could not create or update CiliumNode resource, despite retries")
}

// UpdateCiliumEndpointResource updates the CiliumNode resource representing the
// local node
func (m *VMManager) UpdateCiliumEndpointResource(name, namespace string, id *identity.Identity, addresses []*ciliumv2.AddressPair, nodeIP net.IP) {
        for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		log.Info("Getting Node during an CEP update")
		nr, err := m.ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			log.WithError(err).Warn("Unable to get CiliumNode resource, will retry")
			continue
		}
		log.Info("Getting CEP during an initialization")
                localCEP, err := m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Get(context.TODO(), name, metav1.GetOptions{})
                if err != nil {
                        cep := &ciliumv2.CiliumEndpoint{
                                ObjectMeta: metav1.ObjectMeta{
                                        Name: name,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "cilium.io/v2",
							Kind:               "CiliumNode",
							Name:               nr.ObjectMeta.Name,
							UID:                nr.ObjectMeta.UID,
							BlockOwnerDeletion: func() *bool { a := true; return &a }(),
						},
					},
					Labels: map[string]string{
						"name": name,
					},
                                },
                        }
                        if localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Create(context.TODO(), cep, metav1.CreateOptions{}); err != nil {
                                if errors.IsConflict(err) {
                                        log.WithError(err).Warn("Unable to create CiliumEndpoint resource, will retry")
                                        continue
                                }
                                log.WithError(err).Fatal("Unable to create CiliumEndpoint resource")
                        }
			js, _ := json.Marshal(cep)
			log.Infof("Successfully created CiliumEndpoint resource %s/%s: %s", namespace, name, js)
			js, _ = json.Marshal(localCEP)
			log.Infof("Returned CiliumEndpoint resource %s/%s: %s", namespace, name, js)
		}

		mdl := ciliumv2.EndpointStatus{
			ID: int64(1),
			// ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
			Identity:   getEndpointIdentity(identitymodel.CreateModel(id)),
			Networking: &ciliumv2.EndpointNetworking{
				Addressing: addresses,
				NodeIP:     nodeIP.String(),
			},
			State: string(models.EndpointStateReady), // XXX
			// Encryption:          ciliumv2.EncryptionSpec{Key: int(node.GetIPsecKeyIdentity())},
			// NamedPorts:          e.getNamedPortsModel(),
		}

		if k8sversion.Capabilities().Patch {
			replaceCEPStatus := []k8s.JSONPatch{
				{
					OP:    "replace",
					Path:  "/status",
					Value: mdl,
				},
			}
			var createStatusPatch []byte
			createStatusPatch, err = json.Marshal(replaceCEPStatus)
			if err != nil {
				log.WithError(err).Fatal("json.Marshal(%v) failed", replaceCEPStatus)
			}
			localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Patch(context.TODO(), name,
				types.JSONPatchType, createStatusPatch,	metav1.PatchOptions{},"status")
			if err != nil {
				if errors.IsConflict(err) {
					log.WithError(err).Warn("Unable to update CiliumEndpoint resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to update CiliumEndpoint resource")
			} else {
				log.Info("Successfully patched CiliumEndpoint resource: %v", *localCEP)
				return
			}
		} else {
			localCEP.Status = mdl
                        localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Update(context.TODO(), localCEP, metav1.UpdateOptions{})
			if err != nil {
				if errors.IsConflict(err) {
					log.WithError(err).Warn("Unable to update CiliumEndpoint resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to update CiliumEndpoint resource")
			} else {
				log.Info("Successfully updated CiliumEndpoint resource: %v", *localCEP)
				return
			}
		}
        }
        log.Fatal("Could not create or update CiliumEndpoint resource, despite retries")
}

func getEndpointIdentity(mdlIdentity *models.Identity) (identity *ciliumv2.EndpointIdentity) {
	if mdlIdentity == nil {
		return
	}
	identity = &ciliumv2.EndpointIdentity{
		ID: mdlIdentity.ID,
	}

	identity.Labels = make([]string, len(mdlIdentity.Labels))
	copy(identity.Labels, mdlIdentity.Labels)
	sort.Strings(identity.Labels)
	log.Infof("Got Endpoint Identity: %v", *identity)
	return
}
