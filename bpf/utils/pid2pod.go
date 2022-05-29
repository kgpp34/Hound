package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	errors "github.com/pkg/errors"
)

var (
	kubePattern   = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
)

type PodUserInfo struct {
	Namespace     string
	PodName       string
	PodUID        string
	PodLabels     map[string]string
	ContainerID   string
	ContainerName string
}

type podList struct {
	// We only care about namespace, serviceAccountName and containerID
	Metadata struct {
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string            `json:"namespace"`
			Name      string            `json:"name"`
			UID       string            `json:"uid"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Name        string `json:"name"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func LookUpPodInfo(pid int) (*PodUserInfo, error) {
	containerID, err := LookUpContainerID(pid)
	if err != nil {
		return nil, err
	}

	// Look up the container ID in the local kubelet API.
	// make sure your kubelet --anonymous-auth is true and --authorization-mode is AlwaysAllow
	resp, err := http.Get(fmt.Sprintf("http://localhost:%v/pods", 10250))
	if err != nil {
		return nil, errors.WithMessage(err, "could not lookup container ID in kubelet API")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessage(err, "could not read response from kubelet API")
	}
	var podInfo *podList
	if err := json.Unmarshal(body, &podInfo); err != nil {
		return nil, errors.WithMessage(err, "could not unmarshal response from kubelet API")
	}

	for _, item := range podInfo.Items {
		for _, status := range item.Status.ContainerStatuses {
			if status.ContainerID == "docker://"+containerID {
				return &PodUserInfo{
					Namespace:     item.Metadata.Namespace,
					PodName:       item.Metadata.Name,
					PodUID:        item.Metadata.UID,
					PodLabels:     item.Metadata.Labels,
					ContainerID:   containerID,
					ContainerName: status.Name,
				}, nil
			}
		}
	}
	return nil, nil
}

func LookUpContainerID(pid int) (string, error) {
	// open cgroup by pid
	f, err := os.Open(fmt.Sprint("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	//
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// read each line
		line := scanner.Text()

		// get container id by docker type
		containerParts := dockerPattern.FindStringSubmatch(line)
		if containerParts != nil {
			return containerParts[1], nil
		}

		// get kubenetes container id by kube type
		containerParts = kubePattern.FindStringSubmatch(line)
		if containerParts != nil {
			return containerParts[1], nil
		}
	}

	return "", nil
}
