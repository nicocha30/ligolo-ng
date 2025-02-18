package app

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
)

// App is used to register the grumble
var App = grumble.New(&grumble.Config{
	Name:                  "ligolo-ng",
	Description:           "Ligolo-ng - An advanced, yet simple tunneling tool",
	HelpHeadlineUnderline: true,
	HelpSubCommands:       true,
	HistoryFile:           "ligolo-ng.history",
})

func Ask(question string) bool {
	result := false
	prompt := &survey.Confirm{
		Message: question,
	}
	survey.AskOne(prompt, &result)
	return result
}
