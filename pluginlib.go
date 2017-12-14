package pluginlib

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/kalaspuffar/base64url"
	"github.com/watts-kit/wattsPluginAPISchemes"
	"gopkg.in/alecthomas/kingpin.v2"
)

type (
	// Credential to be created by request
	Credential map[string]interface{}

	// FeatureDescriptor for the PluginDescriptor
	FeatureDescriptor struct {
		Stdin bool `json:"stdin"`
	}

	// ConfigParamsDescriptor for the PluginDescriptor
	ConfigParamsDescriptor struct {
		Name    string      `json:"name"`
		Type    string      `json:"type"`
		Default interface{} `json:"default"`
	}

	// RequestParamsDescriptor for the PluginDescriptor
	RequestParamsDescriptor struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type"`
		Mandatory   bool   `json:"mandatory"`
	}

	// Output represents the plugins json output
	Output map[string]interface{}

	// Action is the type of a method implemented by the plugin to execute an action
	Action (func(Input) Output)

	// SSHHost for RunSSHCommand
	SSHHost string

	// SSHHostList for RunSSHCommand
	SSHHostList []SSHHost

	// AdditionalLogin type
	AdditionalLogin struct {
		UserInfo    map[string]string `json:"user_info"`
		AccessToken string            `json:"access_token"`
	}

	// Input type
	Input struct {
		WaTTSVersion     string                 `json:"watts_version"`
		Action           string                 `json:"action"`
		Conf             map[string]interface{} `json:"conf_params"`
		Params           map[string]interface{} `json:"params"`
		CredentialState  string                 `json:"cred_state"`
		AccessToken      string                 `json:"access_token"`
		UserInfo         map[string]interface{} `json:"user_info"`
		AdditionalLogins []AdditionalLogin      `json:"additional_logins"`
		WaTTSUserID      string                 `json:"watts_userid"`
	}

	// PluginDescriptor describes a plugin to be executed by the wattsPluginLib
	PluginDescriptor struct {
		Author         string
		Version        string
		Description    string
		Name           string
		DeveloperEmail string
		Actions        map[string]Action
		ConfigParams   []ConfigParamsDescriptor
		RequestParams  []RequestParamsDescriptor
		Features       FeatureDescriptor
	}
)

const (
	libVersion = "4.3.2"
)

// PublicKeyFromParams get a public key from the parameters
// also validates the amount of parts of the public key
func (pi *Input) PublicKeyFromParams(key string) (publicKey string) {
	if pk, ok := pi.Params["pub_key"]; ok {
		rawPublicKey, ok := pk.(string)
		CheckOk(ok, 1, "pub_key is no string")

		// parse the public key
		keyElements := strings.Split(rawPublicKey, " ")
		switch len(keyElements) {
		case 2:
			// case key-type + key
			publicKey = rawPublicKey
		case 3:
			// case key-type + key + comment
			publicKey = fmt.Sprintf("%s %s", keyElements[0], keyElements[1])
		default:
			PluginUserError(
				fmt.Sprintf("Cannot parse user provided public key (e = %v)", len(keyElements)),
				"Unable to parse the provided ssh public key",
			)
		}
	}
	return
}

// SSHHostFromConf SSH Host from config values
func (pi *Input) SSHHostFromConf(userKey string, hostKey string) SSHHost {
	return SSHHost(fmt.Sprintf("%s@%s", pi.Conf[userKey], pi.Conf[hostKey]))
}

// SSHHostListFromConf get ssh hosts from a space separated list of ssh hosts
func (pi *Input) SSHHostListFromConf(hostListKey string) SSHHostList {
	listString := pi.Conf[hostListKey].(string)
	list := strings.Split(listString, " ")
	hostList := make(SSHHostList, len(list))
	for i, v := range list {
		hostList[i] = SSHHost(v)
	}
	return hostList
}

// RunSSHCommand run command the SSHHost
func (h *SSHHost) RunSSHCommand(cmdParts ...string) (output string) {
	parameters := append([]string{string(*h)}, cmdParts...)
	cmd := exec.Command("ssh", parameters...)
	outputBytes, err := cmd.Output()
	if err != nil {
		PluginUserError(
			fmt.Sprint(cmdParts, err, cmdParts),
			fmt.Sprintf("Error executing a command on the remote host %s", *h),
		)
	}
	return string(outputBytes)
}

// RunSSHCommandErr like RunSSHCommand, but with error passtrough
func (h *SSHHost) RunSSHCommandErr(cmdParts ...string) (output string, err error) {
	parameters := append([]string{string(*h)}, cmdParts...)
	cmd := exec.Command("ssh", parameters...)
	outputBytes, err := cmd.Output()
	return string(outputBytes), err
}

// RunSSHCommand run command on all hosts in the host list
func (h *SSHHostList) RunSSHCommand(cmdParts ...string) []string {
	l := len(*h)
	output := make([]string, l)
	ch := make(chan string, l)
	wg := sync.WaitGroup{}
	for _, host := range *h {
		wg.Add(1)
		go func(h SSHHost, ch chan string, wg *sync.WaitGroup) {
			o := (&h).RunSSHCommand(cmdParts...)
			ch <- o
			wg.Done()
		}(host, ch, &wg)
	}
	wg.Wait()
	close(ch)
	for o := range ch {
		output = append(output, o)
	}
	return output
}

// TextCredential returns a text credential with valid type
func TextCredential(name string, value string) Credential {
	return Credential{
		"type":  "text",
		"name":  name,
		"value": value,
	}
}

// TextFileCredential returns a textfile credential with valid type
func TextFileCredential(name string, value string, rows int, cols int, saveAs string) Credential {
	return Credential{
		"type":    "textfile",
		"name":    name,
		"save_as": saveAs,
		"value":   value,
		"rows":    rows,
		"cols":    cols,
	}
}

// AutoTextFileCredential returns a credential which tries to derive type and other attributes
// takes a filename for the case that the credential is a textfile
func AutoTextFileCredential(name string, value interface{}, saveAs string) (c Credential) {
	switch value.(type) {
	case string:
		stringValue, ok := value.(string)
		CheckOk(ok, 1, "AutoCredential: got no string")

		lines := strings.Split(stringValue, "\n")
		if len(lines) > 1 {
			longestLineLength := 0
			for _, s := range lines {
				if l := len(s); l > longestLineLength {
					longestLineLength = l
				}
			}
			row := len(lines)
			col := longestLineLength
			c = TextFileCredential(name, stringValue, row+3, col, saveAs)
		} else {
			c = TextCredential(name, stringValue)
		}
	default:
		c = TextCredential(name, fmt.Sprintf("%s", value))
	}
	return c
}

// AutoCredential returns a credential which tries to derive type and other attributes
func AutoCredential(name string, value interface{}) (c Credential) {
	switch value.(type) {
	case string:
		stringValue, ok := value.(string)
		CheckOk(ok, 1, "AutoCredential: got no string")

		lines := strings.Split(stringValue, "\n")
		if len(lines) > 1 {
			longestLineLength := 0
			for _, s := range lines {
				if l := len(s); l > longestLineLength {
					longestLineLength = l
				}
			}
			row := len(lines)
			col := longestLineLength
			c = TextFileCredential(name, stringValue, row+3, col, name+".txt")
		} else {
			c = TextCredential(name, stringValue)
		}
	default:
		c = TextCredential(name, fmt.Sprintf("%s", value))
	}
	return c
}

// Check an error and exit with exitCode if it fails
func Check(err error, exitCode int, msg string) {
	if err != nil {
		var errorMsg string
		if msg != "" {
			errorMsg = fmt.Sprintf("%s - %s", err, msg)
		} else {
			errorMsg = fmt.Sprintf("%s", err)
		}
		terminate(PluginError(errorMsg), exitCode)
	}
	return
}

// CheckOk check if ok is true and exit with exitCode if not
func CheckOk(ok bool, exitCode int, msg string) {
	if !ok {
		terminate(PluginError(msg), exitCode)
	}
	return
}

func printOutput(i interface{}) {
	b := new(bytes.Buffer)

	indentation := ""
	outputTabWidth := "    "
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent(indentation, outputTabWidth)

	err := encoder.Encode(i)
	Check(err, 1, "marshalIndent")
	outputBytes := b.Bytes()
	fmt.Printf("%s", string(outputBytes))
}

func decodeInput(input string) (i Input) {
	bs, err := base64url.Decode(input)
	Check(err, 1, fmt.Sprintf("decoding base64 string - %s", input))

	// validate the input against a scheme
	var testInterface interface{}
	err = json.Unmarshal(bs, &testInterface)
	Check(err, 1, "unmarshaling input")
	validate(testInterface)

	// more thorough check of the input ---
	var testMap map[string]interface{}
	err = json.Unmarshal(bs, &testMap)
	Check(err, 1, "unmarshaling input into map")

	action, ok := testMap["action"].(string)
	CheckOk(ok, 1, "action is not a string")
	if action == "revoke" {
		delete(testMap, "params")
	}
	bs, err = json.Marshal(testMap)
	Check(err, 1, "unmarshaling input into map")
	// ---

	err = json.Unmarshal(bs, &i)
	Check(err, 1, "unmarshaling input")
	return i
}

func actionParameter(pd PluginDescriptor) (o Output) {
	o = Output{
		"conf_params": pd.ConfigParams,
		"request_params": []interface{}{
			pd.RequestParams,
		},
		"features": pd.Features,
		"version":  pd.Version,
		"result":   "ok",
	}

	if pd.DeveloperEmail != "" {
		o["developer_email"] = pd.DeveloperEmail
	}
	return
}

func initializePlugin(input Input, pd PluginDescriptor) {
	var output Output
	// test if plugin is already initialized (via a provided action "isInitialized")
	// isInitialized has to return the an Output with "isInitialized": true if the plugin is already
	// initialized
	if action, ok := pd.Actions["isInitialized"]; ok {
		output = action(input)
		isInitialized, ok := output["isInitialized"].(bool)
		CheckOk(ok, 1, "isInitialized is no bool")
		if isInitialized {
			return
		}
	}

	// initialize the plugin if it has provided an initialize action
	// isInitialized has to return the an Output with "restult": "ok" if the initialization was
	// successful
	if action, ok := pd.Actions["initialize"]; ok {
		output = action(input)
		result, ok := output["result"].(string)
		CheckOk(ok, 1, "result is no string")
		if result == "ok" {
			return
		}
		terminate(output, 1)
	}
}

func executeAction(input Input, pd PluginDescriptor) (output Output) {
	action := input.Action
	switch action {
	case "parameter":
		// we do the parameter action ourself
		output = actionParameter(pd)
		return

	case "request":
		// initialize plugins before request
		initializePlugin(input, pd)

	case "revoke":
		// initialize plugins before revoke
		// this is needed if the state vanishes while a credential is still tracked by watts
		initializePlugin(input, pd)
	}

	// validate the input against the descriptor (if the action was not parameter)
	validatePluginInput(input, pd)

	if actionImplementation, ok := pd.Actions[action]; ok {
		output = actionImplementation(input)
	} else {
		PluginError(fmt.Sprintf("invalid / not implemented plugin action '%s'", action))
	}
	return
}

func validate(pluginInput interface{}) {
	path, err := schemes.PluginInputScheme.Validate(pluginInput)
	Check(err, 1, fmt.Sprintf("on validating plugin input at path %s", path))
	return
}

func validatePluginInput(input Input, pd PluginDescriptor) {

	// check all config parameters for existence and correct type
	for _, cpd := range pd.ConfigParams {
		if paramValue, ok := input.Conf[cpd.Name]; ok {
			expectedType := cpd.Type

			// TODO support more types
			switch paramType := paramValue.(type) {
			case string:
				if expectedType == "string" ||
					expectedType == "text" ||
					expectedType == "textfile" ||
					expectedType == "textarea" {
					continue
				}
			case bool:
				if expectedType == "boolean" {
					continue
				}
			default:
				PluginError(fmt.Sprintf("config parameter %s needs to be of type %s not %s", cpd.Name, cpd.Type, paramType))
			}
		} else {
			PluginError(fmt.Sprintf("config parameter %s needs to be provided", cpd.Name))
		}
	}

	// check all request parameters for existence and correct type
	if input.Action == "request" {
		for _, rpd := range pd.RequestParams {
			if paramValue, ok := input.Params[rpd.Key]; ok {
				expectedType := rpd.Type
				switch paramType := paramValue.(type) {
				case string:
					if expectedType == "string" ||
						expectedType == "text" ||
						expectedType == "textfile" ||
						expectedType == "textarea" {
						continue
					}
				case bool:
					if expectedType == "boolean" {
						continue
					}
				default:
					PluginError(fmt.Sprintf("request parameter %s needs to be of type %s not %s", rpd.Name, rpd.Type, paramType))
				}
			} else {
				// only fail if the request parametr is mandatory
				if rpd.Mandatory {
					PluginError(fmt.Sprintf("request parameter %s needs to be provided", rpd.Key))
				}
			}
		}
	}
}

// terminate print the output and terminate the plugin
func terminate(o Output, exitCode int) {
	printOutput(o)
	os.Exit(exitCode)
}

// PluginDebug prints the interface and exits. *NOT* for production
func PluginDebug(debugOutput interface{}) {
	printOutput(debugOutput)
	os.Exit(1)
	return
}

// PluginGoodRequest to be returned by request if the request yielded a credential
func PluginGoodRequest(credential []Credential, credentialState string) Output {
	return Output{
		"result":     "ok",
		"credential": credential,
		"state":      credentialState,
	}
}

// PluginAdditionalLogin to be returned by request if an additional login is needed
func PluginAdditionalLogin(providerID string, userMsg string) Output {
	return Output{
		"result":   "oidc_login",
		"provider": providerID,
		"msg":      userMsg,
	}
}

// PluginGoodRevoke to be returned by revoke if the revoke succeeded
func PluginGoodRevoke() Output {
	return Output{
		"result": "ok",
	}
}

// PluginError call to indicate an error in the logs, but not to the user
func PluginError(logMsg string) (o Output) {
	o = Output{
		"user_msg": "Internal error, please contact the administrator",
		"log_msg":  logMsg,
		"result":   "error",
	}

	terminate(o, 1)
	return
}

// PluginUserError call to indicate an error in the logs and separately to the user
func PluginUserError(logMsg string, userMsg string) (o Output) {
	o = Output{
		"user_msg": userMsg,
		"log_msg":  logMsg,
		"result":   "error",
	}
	terminate(o, 1)
	return
}

// PluginRun is to be run by the implementing plugin
func PluginRun(pluginDescriptor PluginDescriptor) {
	// Report panics
	defer func() {
		if r := recover(); r != nil {
			PluginError(fmt.Sprint(r))
		}
	}()

	// set features provided by us natively
	pluginDescriptor.Features.Stdin = true

	versionDescription := fmt.Sprintf("(plugin version: %s) (wattsPluginLib version: %s) (wattsPluginAPISchemes version: %s)", pluginDescriptor.Version, libVersion, schemes.MaxWattsVersion)
	description := pluginDescriptor.Description + versionDescription

	app := kingpin.New(pluginDescriptor.Name, description)

	pluginInput := app.Arg("pluginInput (base64url encoded json)", "base64url encoded input").String()
	app.Author(pluginDescriptor.Author)
	app.Version(pluginDescriptor.Version)

	// get input
	kingpin.MustParse(app.Parse(os.Args[1:]))

	var (
		rawInput string
		err      error
		r        rune
	)
	if *pluginInput == "" {
		reader := bufio.NewReader(os.Stdin)

		r, _, err = reader.ReadRune()
		for err == nil {
			rawInput = rawInput + string(r)
			r, _, err = reader.ReadRune()
		}
		if err != io.EOF {
			Check(err, 1, "Reading input")
		}
	} else {
		rawInput = *pluginInput
	}

	input := decodeInput(rawInput)

	// execute the plugin action (validation eventually takes also place)
	output := executeAction(input, pluginDescriptor)

	printOutput(output)
}
