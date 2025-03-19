package web

import "embed"

//go:generate npm install -C ligolo-ng-web
//go:generate npm run build-ligolo -C ligolo-ng-web

//go:embed dist
var LigoloWebFS embed.FS
