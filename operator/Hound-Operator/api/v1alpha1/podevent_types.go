/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PodEventSpec defines the desired state of PodEvent
type PodEventSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	PodName      string `json:"podName,omiempty"`
	K8sNamespace string `json:"k8sNamespace,omiempty"`
	K8sNode      string `json:"k8sNode,omiempty"`
	// Foo is an example field of PodEvent. Edit podevent_types.go to remove/update
	// Foo string `json:"foo,omitempty"`
}

// PodEventStatus defines the observed state of PodEvent
type PodEventStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PodEvent is the Schema for the podevents API
type PodEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodEventSpec   `json:"spec,omitempty"`
	Status PodEventStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PodEventList contains a list of PodEvent
type PodEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodEvent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodEvent{}, &PodEventList{})
}
