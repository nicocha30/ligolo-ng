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

package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
	"os"
	"strings"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)
var Config = viper.New()

func generateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func argon2Hash(password string) (string, error) {
	params := argon2Params{
		time:    3,
		memory:  32 * 1024,
		threads: 4,
		keyLen:  32,
	}
	salt, err := generateRandomBytes(16)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLen)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.memory, params.time, params.threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))

	return encodedHash, nil
}

func CheckAuth(username, password string) bool {
	var shouldFail bool
	users := Config.GetStringMapString("web.users")

	// Find user in config
	userHash, ok := users[username]
	// User not found
	if !ok {
		// Avoid time based attacks
		shouldFail = true
		// Dummy hash
		userHash = "$argon2id$v=19$m=32768,t=3,p=4$Ua+xuAWlGmYIAxyThv3aLg$qO785T0UVM7Ka/bBmmf1yo+XfOt6YoLABQCOiF9Q5M0"
	}
	match, err := comparePasswordAndHash(password, userHash)
	if err != nil {
		logrus.Error(err)
		return false
	}
	if match && !shouldFail {
		return true
	}
	return false
}

func comparePasswordAndHash(password, encodedHash string) (match bool, err error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLen)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *argon2Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &argon2Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLen = uint32(len(hash))

	return p, salt, hash, nil
}

func secureConfigPasswords() {
	users := Config.GetStringMapString("web.users")
	for username, password := range users {
		if !strings.HasPrefix(password, "$argon2") {
			hash, err := argon2Hash(password)
			if err != nil {
				panic(err)
			}
			users[username] = hash
		}
	}
	Config.Set("web.users", users)
}

func SetWebUserPassword(username, password string) error {
	if username == "" {
		return errors.New("web username cannot be empty")
	}
	if password == "" {
		return errors.New("web password cannot be empty")
	}
	hash, err := argon2Hash(password)
	if err != nil {
		return err
	}
	Config.Set("web.users", map[string]string{username: hash})
	return nil
}

func ask(question string) bool {
	result := false
	prompt := &survey.Confirm{
		Message: question,
	}
	survey.AskOne(prompt, &result)
	return result
}

func InitConfig(configFile string, nonInteractive ...bool) {
	var firstStart bool
	noPrompt := len(nonInteractive) > 0 && nonInteractive[0]
	explicitConfigFile := configFile != ""
	if configFile == "" {
		configFile = "ligolo-ng-relay.yaml"
	} else {
		if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
			logrus.Fatal("config file does not exist")
		}
	}

	if explicitConfigFile && (filepath.IsAbs(configFile) || filepath.Dir(configFile) != ".") {
		Config.SetConfigFile(configFile)
	} else {
		Config.SetConfigName(configFile)
	}
	Config.SetConfigType("yaml")
	Config.AddConfigPath(".")
	Config.AddConfigPath("$HOME/.ligolo-ng-relay-proxy")
	Config.AddConfigPath("/etc/ligolo-ng-relay-proxy")
	Config.AddConfigPath("$HOME/.ligolo-proxy")
	Config.AddConfigPath("/etc/ligolo-proxy")

	logrus.Infof("Loading configuration file %s", configFile)
	if err := Config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logrus.Warn("daemon configuration file not found. Creating a new one...")
			f, err := os.Create(configFile)
			firstStart = true
			if err != nil {
				panic(err)
			}
			err = f.Close()
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}

	if firstStart {
		enableWebUI := false
		if !noPrompt {
			enableWebUI = ask("Enable Ligolo-ng Relay WebUI?")
		}
		Config.SetDefault("web.enabled", enableWebUI)
		Config.SetDefault("web.enableui", enableWebUI)
		// Always default to a safe loopback CORS origin so the API can start
		// even when the WebUI is disabled (e.g. `-api -no-web-ui`): gin-contrib/cors
		// panics if AllowOrigins is empty while credentials are enabled.
		Config.SetDefault("web.corsAllowedOrigin", []string{"http://127.0.0.1:8080"})

		if enableWebUI {
			if !noPrompt && ask("Allow CORS Access from https://webui.ligolo.ng?") {
				Config.SetDefault("web.corsAllowedOrigin", []string{"https://webui.ligolo.ng"})
			}
			logrus.Warn("WebUI enabled, default username and login are ligolo:password - make sure to update ligolo-ng-relay.yaml to change credentials!")
		}
	} else {
		Config.SetDefault("web.enabled", false)
		Config.SetDefault("web.enableui", true)
		Config.SetDefault("web.corsAllowedOrigin", []string{"http://127.0.0.1:8080"})
	}
	Config.SetDefault("web.users", map[string]string{"ligolo": "password"})
	Config.SetDefault("web.listen", "127.0.0.1:8080")
	Config.SetDefault("web.debug", false)
	Config.SetDefault("web.logfile", "ui.log")
	Config.SetDefault("web.behindreverseproxy", false)
	Config.SetDefault("web.trustedproxies", []string{"127.0.0.1"})
	Config.SetDefault("web.tls.enabled", false)
	Config.SetDefault("web.tls.selfcert", false)
	Config.SetDefault("web.tls.autocert", false)
	Config.SetDefault("web.tls.certfile", "")
	Config.SetDefault("web.tls.keyfile", "")
	Config.SetDefault("web.tls.alloweddomains", []string{})
	Config.SetDefault("web.tls.selfcertdomain", "ligolo")
	Config.SetDefault("relay.autoheal.enabled", false)
	Config.SetDefault("relay.autoheal.apply", false)
	Config.SetDefault("relay.autoheal.interval_seconds", 30)
	Config.SetDefault("relay.autoheal.with_ipv6", false)
	Config.SetDefault("relay.autoheal.interface_prefix", "ligolo")
	Config.SetDefault("relay.autoheal.start_tunnels", false)
	Config.SetDefault("relay.autoheal.repair", true)
	Config.SetDefault("relay.autoheal.prune_conflicts", false)
	Config.SetDefault("relay.autoheal.failover", true)
	Config.SetDefault("relay.autoheal.max_repair_actions", 10)
	Config.SetDefault("relay.autoheal.max_failovers", 1)
	secureConfigPasswords()

	secret, err := generateRandomBytes(32)
	if err != nil {
		panic(err)
	}
	Config.SetDefault("web.secret", hex.EncodeToString(secret))

	if firstStart {
		Config.SetDefault("interface.ligolosample.routes", []string{"10.254.0.0/24", "10.255.0.0/24"})
		Config.SetDefault("agent.deadbeefcafe.interface", "ligolo")
		Config.SetDefault("agent.deadbeefcafe.autobind", false)
	}
	if err := Config.WriteConfig(); err != nil {
		panic(fmt.Errorf("unable to write config file: %s", err))
	}
}
