package wattsPluginLib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/kalaspuffar/base64url"
	"github.com/indigo-dc/watts-plugin-tester/schemes"
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

	// AdditionalLogin type
	AdditionalLogin struct {
		UserInfo    map[string]string `json:"user_info"`
		AccessToken string            `json:"access_token"`
	}

	// PluginInput type
	PluginInput struct {
		WaTTSVersion     string                 `json:"watts_version"`
		Action           string                 `json:"action"`
		ConfigParams     map[string]interface{} `json:"conf_params"`
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
		ActionRequest (func(Plugin) Output)
		ActionRevoke  (func(Plugin) Output)
		ConfigParams  []ConfigParamsDescriptor
		RequestParams []RequestParamsDescriptor
	}

	// Plugin all necessary data for the request/revoke implementations
	Plugin struct {
		PluginInput PluginInput
	}
)

var (
	libVersion = "0.1.0"
	app         = kingpin.New("wattsPlugin", "WaTTS plugin using wattsPluginLib (" + libVersion + ")")
	pluginInput = app.Arg("input (base64url encoded json)", "base64url encoded input").Required().String()
)

func check(err error, exitCode int, msg string) {
	if err != nil {
		var errorMsg string
		if msg != "" {
			errorMsg = fmt.Sprintf("%s - %s", err, msg)
		} else {
			errorMsg = fmt.Sprintf("%s", err)
		}
		Terminate(PluginError(errorMsg), 1)
	}
	return
}

func printOutput(o Output) {
	b := new(bytes.Buffer)

	indentation := ""
	outputTabWidth := "    "
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent(indentation, outputTabWidth)

	err := encoder.Encode(o)
	check(err, 1, "marshalIndent")
	fmt.Printf("%s", string(b.Bytes()))
}

func decodeInput(input string) (i PluginInput) {
	bs, err := base64url.Decode(input)
	check(err, 1, "decoding base64 string")

	var testInterface interface{}
	err = json.Unmarshal(bs, &testInterface)
	check(err, 1, "unmarshaling input")
	validate(testInterface)

	err = json.Unmarshal(bs, &i)
	check(err, 1, "unmarshaling input")
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

func executeAction(p Plugin, pd PluginDescriptor) (output Output) {
	action := p.PluginInput.Action
	switch action {
	case "parameter":
		output = actionParameter(pd)
	case "request":
		output = pd.ActionRequest(p)
	case "revoke":
		output = pd.ActionRevoke(p)
	default:
		Terminate(PluginError(fmt.Sprintf("invalid plugin action '%s'", action)), 1)
	}
	return
}

func validate(pluginInput interface{}) {
	path, err := schemes.PluginInputScheme.Validate(pluginInput)
	check(err, 1, fmt.Sprintf("on validating plugin input at path %s", path))
	return
}

func getPlugin(pd PluginDescriptor, input PluginInput) (p Plugin) {
	p = Plugin{
		PluginInput: input,
	}
	/*
		if cp := input["config_params"]; cp != nil {
			configParams := cp.(map[string]interface{})
			err := mergo.MergeWithOverwrite(&p.ConfigParams, configParams)
			check(err, 1, "merging config params")
		}
		if rp := input["params"]; rp != nil {
			requestParams := rp.(map[string]interface{})
			err := mergo.MergeWithOverwrite(&p.RequestParams, requestParams)
			check(err, 1, "merging request params")
		}
		(*p).PluginInput = input
	*/
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

// PluginAdditionalLogin to be returned by request if the an additional login is needed
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
func PluginError(logMsg string) Output {
	return Output{
		"user_msg": "Internal error, please contact the administrator",
		"log_msg":  logMsg,
		"result":   "error",
	}
}

// Terminate print the output and terminate the plugin
func Terminate(o Output, exitCode int) {
	printOutput(o)
	os.Exit(exitCode)
}

// PluginRun is to be run by the implementing plugin
func PluginRun(pluginDescriptor PluginDescriptor) {
	app.Author(pluginDescriptor.Author)
	app.Version(pluginDescriptor.Version)

	// get input
	kingpin.MustParse(app.Parse(os.Args[1:]))
	input := decodeInput(*pluginInput)

	// generate plugin
	plugin := getPlugin(pluginDescriptor, input)
	output := executeAction(plugin, pluginDescriptor)
	printOutput(output)
}
