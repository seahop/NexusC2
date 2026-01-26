// internal/templates/hash.go
package templates

// GetHashTemplate returns the hash command template for agents
func GetHashTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Algorithms (short form - server transforms)
	tpl[IdxHashAlgoSha256] = "s"
	tpl[IdxHashAlgoMd5] = "m"
	tpl[IdxHashAlgoAll] = "a"

	// Output prefixes
	tpl[IdxHashPrefixMd5] = "MD5:"
	tpl[IdxHashPrefixSha256] = "SHA256:"

	// Full algorithm names (for output)
	tpl[IdxHashNameSha256] = "sha256"
	tpl[IdxHashNameMd5] = "md5"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeHash,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformHashFlags transforms long algorithm names to short codes for hash command
func TransformHashFlags(command string) string {
	replacements := []struct{ from, to string }{
		{" sha256", " s"},
		{" md5", " m"},
		{" all", " a"},
		{" both", " a"},
	}

	result := command
	for _, r := range replacements {
		result = replaceAllOccurrences(result, r.from, r.to)
	}
	return result
}
