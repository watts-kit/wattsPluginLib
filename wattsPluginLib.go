package wattsPluginLib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/indigo-dc/watts-plugin-tester/schemes"
	"github.com/kalaspuffar/base64url"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type (
	// Credential to be created by request
	Credential struct {
		Name  string      `json:"name"`
		Type  string      `json:"type"`
		Value interface{} `json:"value"`
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
		UserInfo         map[string]string      `json:"user_info"`
		AdditionalLogins []AdditionalLogin      `json:"additional_logins"`
		WaTTSUserID      string                 `json:"watts_userid"`
	}

	// PluginDescriptor describes a plugin to be executed by the wattsPluginLib
	PluginDescriptor struct {
		Author        string
		Version       string
		Description   string
		Name          string
		Actions       map[string]Action
		ConfigParams  []ConfigParamsDescriptor
		RequestParams []RequestParamsDescriptor
	}
)

const (
	libVersion = "2.1.1"
)

// Check check an error and exit with exitCode if it fails
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

func printOutput(i interface{}) {
	b := new(bytes.Buffer)

	indentation := ""
	outputTabWidth := "    "
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent(indentation, outputTabWidth)

	err := encoder.Encode(i)
	Check(err, 1, "marshalIndent")
	fmt.Printf("%s", string(b.Bytes()))
}

func decodeInput(input string) (i Input) {
	bs, err := base64url.Decode(input)
	Check(err, 1, "decoding base64 string")

	// validate the input against a scheme
	var testInterface interface{}
	err = json.Unmarshal(bs, &testInterface)
	Check(err, 1, "unmarshaling input")
	validate(testInterface)

	err = json.Unmarshal(bs, &i)
	Check(err, 1, "unmarshaling input")
	return i
}

func actionParameter(pd PluginDescriptor) Output {
	return Output{
		"conf_params": pd.ConfigParams,
		"request_params": []interface{}{
			pd.RequestParams,
			[]interface{}{},
		},
		"version": pd.Version,
		"result":  "ok",
	}
}

func initializePlugin(input Input, pd PluginDescriptor) {
	var output Output
	// test if plugin is already initialized (via a provided action "isInitialized")
	// isInitialized has to return the an Output with "isInitialized": true if the plugin is already
	// initialized
	if action, ok := pd.Actions["isInitialized"]; ok {
		output = action(input)
		if isInitialized, ok := output["isInitialized"].(bool); ok && isInitialized {
			return
		}
	}

	// initialize the plugin if it has provided an initialize action
	// isInitialized has to return the an Output with "restult": "ok" if the initialization was
	// successful
	if action, ok := pd.Actions["initialize"]; ok {
		output = action(input)
		if result, ok := output["result"].(string); ok && result == "ok" {
			return
		}
		terminate(output, 1)
	}
}

func executeAction(input Input, pd PluginDescriptor) (output Output) {
	switch action := input.Action; action {
	case "parameter":
		// we do the parameter action ourself
		actionParameter(pd)

	case "request":
		// initialize plugins before all requests
		initializePlugin(input, pd)

	default:
		if actionImplementation, ok := pd.Actions[action]; ok {
			output = actionImplementation(input)
		} else {
			PluginError(fmt.Sprintf("invalid / not implemented plugin action '%s'", action))
		}
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
			actualType := ""

			// TODO support more types
			switch paramType := paramValue.(type) {
			case string:
				actualType = "string"
			case bool:
				actualType = "bool"
			default:
				PluginError(fmt.Sprintf("config parameter %s needs to be of type %s (is %s)",
					cpd.Name, cpd.Type, paramType))
			}

			if expectedType != actualType {
				PluginError(fmt.Sprintf("config parameter %s needs to be of type %s", cpd.Name, cpd.Type))
			}
		} else {
			PluginError(fmt.Sprintf("config parameter %s needs to be provided", cpd.Name))
		}
	}

	// check all request parameters for existence and correct type
	for _, rpd := range pd.RequestParams {
		if paramValue, ok := input.Params[rpd.Key]; ok {
			expectedType := rpd.Type
			actualType := ""

			// TODO support more types
			switch paramType := paramValue.(type) {
			case string:
				actualType = "string"
			case bool:
				actualType = "bool"
			default:
				PluginError(fmt.Sprintf("request parameter %s needs to be of type %s (is %s)",
					rpd.Name, rpd.Type, paramType))
			}

			if expectedType != actualType {
				PluginError(fmt.Sprintf("request parameter %s needs to be of type %s", rpd.Key, rpd.Type))
			}
		} else {
			// only fail if the request parametr is mandatory
			if rpd.Mandatory {
				PluginError(fmt.Sprintf("request parameter %s needs to be provided", rpd.Key))
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

// PluginError call to indicate an error
func PluginError(logMsg string) (o Output) {
	o = Output{
		"user_msg": "Internal error, please contact the administrator",
		"log_msg":  logMsg,
		"result":   "error",
	}

	terminate(o, 1)
	return
}

// PluginRun is to be run by the implementing plugin
func PluginRun(pluginDescriptor PluginDescriptor) {
	app := kingpin.New(
		pluginDescriptor.Name,
		pluginDescriptor.Description+" (plugin version: "+pluginDescriptor.Version+") (wattsPluginLib version: "+libVersion+")")
	pluginInput := app.Arg("pluginInput (base64url encoded json)", "base64url encoded input").Required().Envar("WATTS_PARAMETER").String()
	app.Author(pluginDescriptor.Author)
	app.Version(pluginDescriptor.Version)

	// get input
	kingpin.MustParse(app.Parse(os.Args[1:]))
	input := decodeInput(*pluginInput)

	// validate the input against the descriptor
	validatePluginInput(input, pluginDescriptor)

	// execute the plugin action
	output := executeAction(input, pluginDescriptor)
	printOutput(output)
}
