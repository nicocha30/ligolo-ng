package app

import "github.com/desertbit/grumble"

// App is used to register the grumble
var App = grumble.New(&grumble.Config{
	Name:                  "ligolo-ng",
	Description:           "Ligolo-ng - An advanced, yet simple tunneling tool",
	HelpHeadlineUnderline: true,
	HelpSubCommands:       true,
})

func init() {
	App.SetPrintASCIILogo(func(a *grumble.App) {
		a.Println("    __    _             __                       ")
		a.Println("   / /   (_)___ _____  / /___        ____  ____ _")
		a.Println("  / /   / / __ `/ __ \\/ / __ \\______/ __ \\/ __ `/")
		a.Println(" / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / ")
		a.Println("/_____/_/\\__, /\\____/_/\\____/     /_/ /_/\\__, /  ")
		a.Println("        /____/                          /____/   \n")
		a.Println("  Made in France ♥            by @Nicocha30!\n")
	})
}
