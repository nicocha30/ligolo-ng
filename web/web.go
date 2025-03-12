package web

import "embed"

//go:generate npm install
//go:generate npm run build

//go:embed dist
var LigoloWebFS embed.FS
