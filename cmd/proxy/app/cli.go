// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package app

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/desertbit/grumble"
)

// App is used to register the grumble
var App = grumble.New(&grumble.Config{
	Name:                  "ligolo-ng-relay",
	Description:           "Ligolo-ng Relay - A maintained relay-chain fork of upstream Ligolo-ng",
	HelpHeadlineUnderline: true,
	HelpSubCommands:       true,
	HistoryFile:           "ligolo-ng-relay.history",
})

func ask(question string) bool {
	result := false
	prompt := &survey.Confirm{
		Message: question,
	}
	survey.AskOne(prompt, &result)
	return result
}
