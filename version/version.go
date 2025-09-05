package version

import "fmt"

const (
	Name      string = "imap"
	Version   string = "1.3.1"
	GitCommit string = "25e39e5c11229e7a5bd09b7d114c7ac4d5ce6469"
	GoVersion string = "1.24.6"
	BuildDate string = "2025-09-05T14:07:14Z"
	GitDirty  string = ""
)

var (
	PluginVersion = fmt.Sprintf("%s-%s", Version, GitDirty)

	HumanVersion = fmt.Sprintf("%s v%s (%s) %s", Name, Version, GitCommit, GitDirty)
)
