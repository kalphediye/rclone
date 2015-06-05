// Read, write and edit the config file

package fs

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/user"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Unknwon/goconfig"
	"github.com/mreiferson/go-httpclient"
	"github.com/ogier/pflag"
)

const (
	configFileName = ".rclone.conf"
)

type SizeSuffix int64

// Global
var (
	// Config file
	ConfigFile *goconfig.ConfigFile
	// Home directory
	HomeDir = configHome()
	// Config file path
	ConfigPath = path.Join(HomeDir, configFileName)
	// Global config
	Config = &ConfigInfo{}
	// Flags
	verbose        = pflag.BoolP("verbose", "v", false, "Print lots more stuff")
	quiet          = pflag.BoolP("quiet", "q", false, "Print as little stuff as possible")
	modifyWindow   = pflag.DurationP("modify-window", "", time.Nanosecond, "Max time diff to be considered the same")
	checkers       = pflag.IntP("checkers", "", 8, "Number of checkers to run in parallel.")
	transfers      = pflag.IntP("transfers", "", 4, "Number of file transfers to run in parallel.")
	configFile     = pflag.StringP("config", "", ConfigPath, "Config file.")
	checkSum       = pflag.BoolP("checksum", "c", false, "Skip based on checksum, not mod-time & size")
	dryRun         = pflag.BoolP("dry-run", "n", false, "Do a trial run with no permanent changes")
	connectTimeout = pflag.DurationP("contimeout", "", 60*time.Second, "Connect timeout")
	timeout        = pflag.DurationP("timeout", "", 5*60*time.Second, "IO idle timeout")
	bwLimit        SizeSuffix
)

func init() {
	pflag.VarP(&bwLimit, "bwlimit", "", "Bandwidth limit in kBytes/s, or use suffix k|M|G")
}

// Turn SizeSuffix into a string
func (x SizeSuffix) String() string {
	scaled := float64(0)
	suffix := ""
	switch {
	case x == 0:
		return "0"
	case x < 1024*1024:
		scaled = float64(x) / 1024
		suffix = "k"
	case x < 1024*1024*1024:
		scaled = float64(x) / 1024 / 1024
		suffix = "M"
	default:
		scaled = float64(x) / 1024 / 1024 / 1024
		suffix = "G"
	}
	if math.Floor(scaled) == scaled {
		return fmt.Sprintf("%.0f%s", scaled, suffix)
	}
	return fmt.Sprintf("%.3f%s", scaled, suffix)
}

// Set a SizeSuffix
func (x *SizeSuffix) Set(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("Empty string")
	}
	suffix := s[len(s)-1]
	suffixLen := 1
	var multiplier float64
	switch suffix {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.':
		suffixLen = 0
		multiplier = 1 << 10
	case 'k', 'K':
		multiplier = 1 << 10
	case 'm', 'M':
		multiplier = 1 << 20
	case 'g', 'G':
		multiplier = 1 << 30
	default:
		return fmt.Errorf("Bad suffix %q", suffix)
	}
	s = s[:len(s)-suffixLen]
	value, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	if value < 0 {
		return fmt.Errorf("Size can't be negative %q", s)
	}
	value *= multiplier
	*x = SizeSuffix(value)
	return nil
}

// Check it satisfies the interface
var _ pflag.Value = (*SizeSuffix)(nil)

// Filesystem config options
type ConfigInfo struct {
	Verbose        bool
	Quiet          bool
	DryRun         bool
	CheckSum       bool
	ModifyWindow   time.Duration
	Checkers       int
	Transfers      int
	ConnectTimeout time.Duration // Connect timeout
	Timeout        time.Duration // Data channel timeout
}

// Transport returns an http.RoundTripper with the correct timeouts
func (ci *ConfigInfo) Transport() http.RoundTripper {
	return &httpclient.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: ci.Checkers + ci.Transfers + 1,

		// ConnectTimeout, if non-zero, is the maximum amount of time a dial will wait for
		// a connect to complete.
		ConnectTimeout: ci.ConnectTimeout,

		// ResponseHeaderTimeout, if non-zero, specifies the amount of
		// time to wait for a server's response headers after fully
		// writing the request (including its body, if any). This
		// time does not include the time to read the response body.
		ResponseHeaderTimeout: ci.Timeout,

		// RequestTimeout, if non-zero, specifies the amount of time for the entire
		// request to complete (including all of the above timeouts + entire response body).
		// This should never be less than the sum total of the above two timeouts.
		//RequestTimeout: NOT SET,

		// ReadWriteTimeout, if non-zero, will set a deadline for every Read and
		// Write operation on the request connection.
		ReadWriteTimeout: ci.Timeout,
	}
}

// Transport returns an http.Client with the correct timeouts
func (ci *ConfigInfo) Client() *http.Client {
	return &http.Client{
		Transport: ci.Transport(),
	}
}

// Find the config directory
func configHome() string {
	// Find users home directory
	usr, err := user.Current()
	if err == nil {
		return usr.HomeDir
	}
	// Fall back to reading $HOME - work around user.Current() not
	// working for cross compiled binaries on OSX.
	// https://github.com/golang/go/issues/6376
	home := os.Getenv("HOME")
	if home != "" {
		return home
	}
	log.Printf("Couldn't find home directory or read HOME environment variable.")
	log.Printf("Defaulting to storing config in current directory.")
	log.Printf("Use -config flag to workaround.")
	log.Printf("Error was: %v", err)
	return ""
}

// Loads the config file
func LoadConfig() {
	// Read some flags if set
	//
	// FIXME read these from the config file too
	Config.Verbose = *verbose
	Config.Quiet = *quiet
	Config.ModifyWindow = *modifyWindow
	Config.Checkers = *checkers
	Config.Transfers = *transfers
	Config.DryRun = *dryRun
	Config.Timeout = *timeout
	Config.ConnectTimeout = *connectTimeout
	Config.CheckSum = *checkSum

	ConfigPath = *configFile

	// Load configuration file.
	var err error
	ConfigFile, err = goconfig.LoadConfigFile(ConfigPath)
	if err != nil {
		log.Printf("Failed to load config file %v - using defaults", ConfigPath)
		ConfigFile, err = goconfig.LoadConfigFile(os.DevNull)
		if err != nil {
			log.Fatalf("Failed to read null config file: %v", err)
		}
	}

	// Start the token bucket limiter
	startTokenBucket()
}

// Save configuration file.
func SaveConfig() {
	err := goconfig.SaveConfigFile(ConfigFile, ConfigPath)
	if err != nil {
		log.Fatalf("Failed to save config file: %v", err)
	}
	err = os.Chmod(ConfigPath, 0600)
	if err != nil {
		log.Printf("Failed to set permissions on config file: %v", err)
	}
}

// Show an overview of the config file
func ShowRemotes() {
	remotes := ConfigFile.GetSectionList()
	if len(remotes) == 0 {
		return
	}
	sort.Strings(remotes)
	fmt.Printf("%-20s %s\n", "Name", "Type")
	fmt.Printf("%-20s %s\n", "====", "====")
	for _, remote := range remotes {
		fmt.Printf("%-20s %s\n", remote, ConfigFile.MustValue(remote, "type"))
	}
}

// ChooseRemote chooses a remote name
func ChooseRemote() string {
	remotes := ConfigFile.GetSectionList()
	sort.Strings(remotes)
	return Choose("remote", remotes, nil, false)
}

// Read some input
func ReadLine() string {
	buf := bufio.NewReader(os.Stdin)
	line, err := buf.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read line: %v", err)
	}
	return strings.TrimSpace(line)
}

// Command - choose one
func Command(commands []string) byte {
	opts := []string{}
	for _, text := range commands {
		fmt.Printf("%c) %s\n", text[0], text[1:])
		opts = append(opts, text[:1])
	}
	optString := strings.Join(opts, "")
	optHelp := strings.Join(opts, "/")
	for {
		fmt.Printf("%s> ", optHelp)
		result := strings.ToLower(ReadLine())
		if len(result) != 1 {
			continue
		}
		i := strings.Index(optString, string(result[0]))
		if i >= 0 {
			return result[0]
		}
	}
}

// Asks the user for Yes or No and returns true or false
func Confirm() bool {
	return Command([]string{"yYes", "nNo"}) == 'y'
}

// Choose one of the defaults or type a new string if newOk is set
func Choose(what string, defaults, help []string, newOk bool) string {
	fmt.Printf("Choose a number from below")
	if newOk {
		fmt.Printf(", or type in your own value")
	}
	fmt.Println()
	for i, text := range defaults {
		if help != nil {
			parts := strings.Split(help[i], "\n")
			for _, part := range parts {
				fmt.Printf(" * %s\n", part)
			}
		}
		fmt.Printf("%2d) %s\n", i+1, text)
	}
	for {
		fmt.Printf("%s> ", what)
		result := ReadLine()
		i, err := strconv.Atoi(result)
		if err != nil {
			if newOk {
				return result
			}
			continue
		}
		if i >= 1 && i <= len(defaults) {
			return defaults[i-1]
		}
	}
}

// Show the contents of the remote
func ShowRemote(name string) {
	fmt.Printf("--------------------\n")
	fmt.Printf("[%s]\n", name)
	for _, key := range ConfigFile.GetKeyList(name) {
		fmt.Printf("%s = %s\n", key, ConfigFile.MustValue(name, key))
	}
	fmt.Printf("--------------------\n")
}

// Print the contents of the remote and ask if it is OK
func OkRemote(name string) bool {
	ShowRemote(name)
	switch i := Command([]string{"yYes this is OK", "eEdit this remote", "dDelete this remote"}); i {
	case 'y':
		return true
	case 'e':
		return false
	case 'd':
		ConfigFile.DeleteSection(name)
		return true
	default:
		log.Printf("Bad choice %d", i)
	}
	return false
}

// Runs the config helper for the remote if needed
func RemoteConfig(name string) {
	fmt.Printf("Remote config\n")
	fsName := ConfigFile.MustValue(name, "type")
	if fsName == "" {
		log.Fatalf("Couldn't find type of fs for %q", name)
	}
	f, err := Find(fsName)
	if err != nil {
		log.Fatalf("Didn't find filing system: %v", err)
	}
	if f.Config != nil {
		f.Config(name)
	}
}

// Choose an option
func ChooseOption(o *Option) string {
	fmt.Println(o.Help)
	if len(o.Examples) > 0 {
		var values []string
		var help []string
		for _, example := range o.Examples {
			values = append(values, example.Value)
			help = append(help, example.Help)
		}
		return Choose(o.Name, values, help, true)
	}
	fmt.Printf("%s> ", o.Name)
	return ReadLine()
}

// Make a new remote
func NewRemote(name string) {
	fmt.Printf("What type of source is it?\n")
	types := []string{}
	for _, item := range fsRegistry {
		types = append(types, item.Name)
	}
	newType := Choose("type", types, nil, false)
	ConfigFile.SetValue(name, "type", newType)
	fs, err := Find(newType)
	if err != nil {
		log.Fatalf("Failed to find fs: %v", err)
	}
	for _, option := range fs.Options {
		ConfigFile.SetValue(name, option.Name, ChooseOption(&option))
	}
	RemoteConfig(name)
	if OkRemote(name) {
		SaveConfig()
		return
	}
	EditRemote(name)
}

// Edit a remote
func EditRemote(name string) {
	ShowRemote(name)
	fmt.Printf("Edit remote\n")
	for {
		for _, key := range ConfigFile.GetKeyList(name) {
			value := ConfigFile.MustValue(name, key)
			fmt.Printf("Press enter to accept current value, or type in a new one\n")
			fmt.Printf("%s = %s>", key, value)
			newValue := ReadLine()
			if newValue != "" {
				ConfigFile.SetValue(name, key, newValue)
			}
		}
		RemoteConfig(name)
		if OkRemote(name) {
			break
		}
	}
	SaveConfig()
}

// Delete a remote
func DeleteRemote(name string) {
	ConfigFile.DeleteSection(name)
	SaveConfig()
}

// Edit the config file interactively
func EditConfig() {
	for {
		haveRemotes := len(ConfigFile.GetSectionList()) != 0
		what := []string{"eEdit existing remote", "nNew remote", "dDelete remote", "qQuit config"}
		if haveRemotes {
			fmt.Printf("Current remotes:\n\n")
			ShowRemotes()
			fmt.Printf("\n")
		} else {
			fmt.Printf("No remotes found - make a new one\n")
			what = append(what[1:2], what[3])
		}
		switch i := Command(what); i {
		case 'e':
			name := ChooseRemote()
			EditRemote(name)
		case 'n':
		nameLoop:
			for {
				fmt.Printf("name> ")
				name := ReadLine()
				switch {
				case name == "":
					fmt.Printf("Can't use empty name\n")
				case isDriveLetter(name):
					fmt.Printf("Can't use %q as it can be confused a drive letter\n", name)
				default:
					NewRemote(name)
					break nameLoop
				}
			}
		case 'd':
			name := ChooseRemote()
			DeleteRemote(name)
		case 'q':
			return
		}
	}
}
