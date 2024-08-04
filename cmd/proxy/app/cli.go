package app

import "github.com/desertbit/grumble"

// App is used to register the grumble
var App = grumble.New(&grumble.Config{
	Name:                  "ligolo-ng",
	Description:           "Ligolo-ng - An advanced, yet simple tunneling tool",
	HelpHeadlineUnderline: true,
	HelpSubCommands:       true,
	HistoryFile:           "ligolo-ng.history",
})
