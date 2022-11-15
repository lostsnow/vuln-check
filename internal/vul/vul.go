package vul

const (
	ScanOK        = "OK"
	ScanMissing   = "Missing"
	ScanWrong     = "Wrong"
	ScanNone      = "None"
	ScanNoSupport = "NoSupport"
	ScanNoConfirm = "NoConfirm"
)

const (
	None         = "none"
	CmdInjection = "cmd-injection"
)

type Vul struct {
	App           string
	AppVersion    string
	URLPath       string
	VulType       string
	VulScanResult string
	Description   string
}
