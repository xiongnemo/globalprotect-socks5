package browserauth

import "os"

var (
	osMkdirTemp = os.MkdirTemp
	osRemoveAll = os.RemoveAll
	osWriteFile = os.WriteFile
)
