package remoteScript

import (
	"bytes"
	"encoding/json"
	"github.com/kalaspuffar/base64url"
	"regexp"
	"os/exec"
)

func encodeRemoteScriptParameter(parameter map[string]interface{}) (string, error) {
	parameterBytes, err := json.Marshal(parameter)
	if err != nil {
		return "", err
	}
	return base64url.Encode(parameterBytes), nil
}

// ExecuteRemoteScriptOnHosts using an existing ssh setup
// issues on every host: <command> <parameter>
// note that parameter gets marshaled into a json string and base64 encoded
func ExecuteRemoteScriptOnHosts(
		remoteCommand string, parameter map[string]interface{}, hostList []string) (
			hostReplies map[string](map[string]interface{}), err error) {

	for _, userAndHost := range hostList {
		// extract host from user@host
		regex, err := regexp.Compile("[^@]+$")
		if err != nil {
			return nil, err
		}
		host := regex.FindString(userAndHost)

		// encode the parameter
		remoteParameter, err := encodeRemoteScriptParameter(parameter)
		if err != nil {
			return nil, err
		}

		// execute the ssh command
		cmd := exec.Command("ssh", userAndHost, remoteCommand, remoteParameter)
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return nil, err
		}

		// checking the output of the ssh command
		var sshCmdOutput map[string]interface{}
		err = json.Unmarshal(out.Bytes(), &sshCmdOutput)
		if err != nil {
			return nil, err
		}
		hostReplies[host] = sshCmdOutput
	}
	return
}
