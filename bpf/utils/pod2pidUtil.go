package utils

import (
	"bytes"
	"log"
	"os/exec"
)

const (
	pod2pidCmdPrefix = `./pod2pid.sh`
)

func getPodHostIp(podName string) (string, error) {
	var b bytes.Buffer

	b.WriteString(pod2pidCmdPrefix)
	b.WriteString(" ")
	b.WriteString(podName)

	cmd := exec.Command("/bin/bash", "-c", b.String())

	out, err := cmd.Output()
	if err != nil {
		log.Printf("Execute Shell:%s failed with error:%s", cmd, err.Error())
		return "", err
	}

	pid := string(out)
	return pid, nil
}
