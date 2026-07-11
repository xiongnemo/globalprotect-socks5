package browserauth

import "os"

var (
	osChmod     = os.Chmod
	osMkdirAll  = os.MkdirAll
	osMkdirTemp = os.MkdirTemp
	osRemoveAll = os.RemoveAll
	osWriteFile = os.WriteFile
)
