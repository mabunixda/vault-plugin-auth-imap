package version

import "fmt"

var (
	Name      string = "vault-plugin-auth-imap"
	Version   string // current version
	GitCommit string // current git commit
	GoVersion string // current go version
	BuildDate string // current build date
	GitDirty  string // was build on a dirty git repo...

	PluginVersion = fmt.Sprintf("%s%s", Version, GitDirty)

	HumanVersion = fmt.Sprintf("%s v%s (%s) %s", Name, Version, GitCommit, GitDirty)
)
