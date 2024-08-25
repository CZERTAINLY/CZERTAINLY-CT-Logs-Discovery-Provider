package model

import (
	"fmt"
)

// ProgrammingLanguageEnum : Definition of programming languages used for code
type ProgrammingLanguageEnum string

// List of ProgrammingLanguageEnum
const (
	APACHECONF ProgrammingLanguageEnum = "apacheconf"
	BASH       ProgrammingLanguageEnum = "bash"
	BASIC      ProgrammingLanguageEnum = "basic"
	C          ProgrammingLanguageEnum = "c"
	CSHARP     ProgrammingLanguageEnum = "csharp"
	CPP        ProgrammingLanguageEnum = "cpp"
	CSS        ProgrammingLanguageEnum = "css"
	DOCKER     ProgrammingLanguageEnum = "docker"
	FSHARP     ProgrammingLanguageEnum = "fsharp"
	GHERKIN    ProgrammingLanguageEnum = "gherkin"
	GIT        ProgrammingLanguageEnum = "git"
	GO         ProgrammingLanguageEnum = "go"
	GRAPHQL    ProgrammingLanguageEnum = "graphql"
	HTML       ProgrammingLanguageEnum = "html"
	HTTP       ProgrammingLanguageEnum = "http"
	INI        ProgrammingLanguageEnum = "ini"
	JAVA       ProgrammingLanguageEnum = "java"
	JAVASCRIPT ProgrammingLanguageEnum = "javascript"
	JSON       ProgrammingLanguageEnum = "json"
	KOTLIN     ProgrammingLanguageEnum = "kotlin"
	LATEX      ProgrammingLanguageEnum = "latex"
	LISP       ProgrammingLanguageEnum = "lisp"
	MAKEFILE   ProgrammingLanguageEnum = "makefile"
	MARKDOWN   ProgrammingLanguageEnum = "markdown"
	MATLAB     ProgrammingLanguageEnum = "matlab"
	NGINX      ProgrammingLanguageEnum = "nginx"
	OBJECTIVEC ProgrammingLanguageEnum = "objectivec"
	PERL       ProgrammingLanguageEnum = "perl"
	PHP        ProgrammingLanguageEnum = "php"
	POWERSHELL ProgrammingLanguageEnum = "powershell"
	PROPERTIES ProgrammingLanguageEnum = "properties"
	PYTHON     ProgrammingLanguageEnum = "python"
	RUBY       ProgrammingLanguageEnum = "ruby"
	RUST       ProgrammingLanguageEnum = "rust"
	SMALLTALK  ProgrammingLanguageEnum = "smalltalk"
	SQL        ProgrammingLanguageEnum = "sql"
	TYPESCRIPT ProgrammingLanguageEnum = "typescript"
	VBNET      ProgrammingLanguageEnum = "vbnet"
	XQUERY     ProgrammingLanguageEnum = "xquery"
	XML        ProgrammingLanguageEnum = "xml"
	YAML       ProgrammingLanguageEnum = "yaml"
)

// AllowedProgrammingLanguageEnumEnumValues is all the allowed values of ProgrammingLanguageEnum enum
var AllowedProgrammingLanguageEnumEnumValues = []ProgrammingLanguageEnum{
	"apacheconf",
	"bash",
	"basic",
	"c",
	"csharp",
	"cpp",
	"css",
	"docker",
	"fsharp",
	"gherkin",
	"git",
	"go",
	"graphql",
	"html",
	"http",
	"ini",
	"java",
	"javascript",
	"json",
	"kotlin",
	"latex",
	"lisp",
	"makefile",
	"markdown",
	"matlab",
	"nginx",
	"objectivec",
	"perl",
	"php",
	"powershell",
	"properties",
	"python",
	"ruby",
	"rust",
	"smalltalk",
	"sql",
	"typescript",
	"vbnet",
	"xquery",
	"xml",
	"yaml",
}

// validProgrammingLanguageEnumEnumValue provides a map of ProgrammingLanguageEnums for fast verification of use input
var validProgrammingLanguageEnumEnumValues = map[ProgrammingLanguageEnum]struct{}{
	"apacheconf": {},
	"bash":       {},
	"basic":      {},
	"c":          {},
	"csharp":     {},
	"cpp":        {},
	"css":        {},
	"docker":     {},
	"fsharp":     {},
	"gherkin":    {},
	"git":        {},
	"go":         {},
	"graphql":    {},
	"html":       {},
	"http":       {},
	"ini":        {},
	"java":       {},
	"javascript": {},
	"json":       {},
	"kotlin":     {},
	"latex":      {},
	"lisp":       {},
	"makefile":   {},
	"markdown":   {},
	"matlab":     {},
	"nginx":      {},
	"objectivec": {},
	"perl":       {},
	"php":        {},
	"powershell": {},
	"properties": {},
	"python":     {},
	"ruby":       {},
	"rust":       {},
	"smalltalk":  {},
	"sql":        {},
	"typescript": {},
	"vbnet":      {},
	"xquery":     {},
	"xml":        {},
	"yaml":       {},
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v ProgrammingLanguageEnum) IsValid() bool {
	_, ok := validProgrammingLanguageEnumEnumValues[v]
	return ok
}

// NewProgrammingLanguageEnumFromValue returns a pointer to a valid ProgrammingLanguageEnum
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewProgrammingLanguageEnumFromValue(v string) (ProgrammingLanguageEnum, error) {
	ev := ProgrammingLanguageEnum(v)
	if ev.IsValid() {
		return ev, nil
	} else {
		return "", fmt.Errorf("invalid value '%v' for ProgrammingLanguageEnum: valid values are %v", v, AllowedProgrammingLanguageEnumEnumValues)
	}
}

// AssertProgrammingLanguageEnumRequired checks if the required fields are not zero-ed
func AssertProgrammingLanguageEnumRequired(obj ProgrammingLanguageEnum) error {
	return nil
}

// AssertProgrammingLanguageEnumConstraints checks if the values respects the defined constraints
func AssertProgrammingLanguageEnumConstraints(obj ProgrammingLanguageEnum) error {
	return nil
}
