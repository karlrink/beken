module gitlab.com/krink/beken-touer/ubeken

go 1.18

replace gitlab.com/krink/ubeken-touer/ubeken/kes => ./kes/gopkg/kes

require (
	github.com/fernet/fernet-go v0.0.0-20211208181803-9f70042a33ee
	github.com/mattn/go-sqlite3 v1.14.17
)
