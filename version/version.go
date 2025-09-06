package version

import "fmt"

var (
	Name      string = "imap"
	Version   string = "v1.3.0"
	GitCommit string = "d5dcfeccb9bfe900b763900e162a5a739fa670d2"
	GoVersion string = "1.24.6"
	BuildDate string = "2025-08-22T17:32:27Z"
	GitDirty  string = ""

	PluginVersion = fmt.Sprintf("%s%s", Version, GitDirty)
	HumanVersion  = fmt.Sprintf("%s v%s (%s) %s", Name, Version, GitCommit, GitDirty)

)
