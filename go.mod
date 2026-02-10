module github.com/ldsec/crisp

go 1.16

// This line is CRITICAL. It tells Go that when the code asks for
// "github.com/ldsec/crisp", it should look in the current folder (.)
replace github.com/ldsec/crisp => ./

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/tuneinsight/lattigo v1.3.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/sys v0.0.0-20211007075335-d3039528d8ac // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect

// You may see other dependencies here after running 'go mod tidy'
// Keep them, but ensure lattigo is strictly v2.x
)

replace github.com/tuneinsight/lattigo/v2 => github.com/ldsec/lattigo/v2 v2.4.1

replace github.com/ldsec/CRISP-private => ./
