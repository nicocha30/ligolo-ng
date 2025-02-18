package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

func InitConfig(configFile string) {
	var firstStart bool
	if configFile == "" {
		configFile = "ligolo-ng.yaml"
	} else {
		if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
			logrus.Fatal("config file does not exist")
		}
	}
	Config.SetConfigName(configFile)
	Config.SetConfigType("yaml")
	Config.AddConfigPath(".")
	Config.AddConfigPath("$HOME/.ligolo-proxy")
	Config.AddConfigPath("/etc/ligolo-proxy")

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

	Config.SetDefault("web.enabled", false)
	Config.SetDefault("web.listen", ":8080")
	Config.SetDefault("web.corsAllowedOrigin", []string{"https://webui.ligolo.ng"})
	Config.SetDefault("web.debug", false)
	Config.SetDefault("web.behindreverseproxy", false)
	Config.SetDefault("web.users", map[string]string{"ligolo": "password"})
	Config.SetDefault("web.trustedproxies", []string{"127.0.0.1"})
	secureConfigPasswords()

	secret, err := generateRandomBytes(32)
	if err != nil {
		panic(err)
	}
	Config.SetDefault("web.secret", hex.EncodeToString(secret))

	if firstStart {
		Config.SetDefault("interface.ligolo.routes", []string{"10.254.0.0/24", "10.255.0.0/24"})
		Config.SetDefault("agent.deadbeefcafe.interface", "ligolo")
		Config.SetDefault("agent.deadbeefcafe.autobind", false)
	}
	if err := Config.WriteConfig(); err != nil {
		panic(fmt.Errorf("unable to write config file: %s", err))
	}
}
