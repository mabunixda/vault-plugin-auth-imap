package version

import "fmt"

var (
	Name      string
	Version   string
	GitCommit string
	GoVersion string
	BuildDate string
	GitDirty  string

	PluginVersion = fmt.Sprintf("%s%s", Version, GitDirty)
	HumanVersion  = fmt.Sprintf("%s v%s (%s) %s", Name, Version, GitCommit, GitDirty)
)
