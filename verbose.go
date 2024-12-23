package verbose

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const VERSION = "0.1.0"

// Dir defines the location of the verbose.log file
// this package will create. This package will truncate
// the verbose.log file each time init is executed on
// the package
var Dir string
var vLogr *Logger

// Common Aliases

var To = SanitizeTo
var Tof = SanitizefTo
var Plain = toAsis
var Plainf = toAsf
var Raw = toAsis
var Rawf = toAsf
var Expose = toAsis
var Exposef = toAsf
var Hide = Sanitize
var Hidef = Sanitizef
var Printf = Sanitizef
var Print = Sanitize
var Println = Sanitize
var Sprint = Sanitize
var Sprintf = Sanitizef

func Trace(v ...interface{}) {
	vLogr.Trace(v...)
}

func Tracef(format string, v ...interface{}) {
	vLogr.Tracef(format, v...)
}

func TraceReturn(v ...interface{}) error {
	return vLogr.TraceReturn(v...)
}

func TracefReturn(format string, v ...interface{}) error {
	return vLogr.TracefReturn(format, v...)
}

func Return(v ...interface{}) error {
	vLogr.Println(v...)
	return fmt.Errorf("%v", v...)
}

// Returnf will log the formatted data and will return an error type
func Returnf(format string, v ...interface{}) error {
	vLogr.Printf(format, v...)
	return fmt.Errorf(format, v...)
}

func AsLn(args ...interface{}) {
	vLogr.Println(args...)
}

func toAsLn(customerLogger *log.Logger, args ...interface{}) {
	customerLogger.Println(args...)
}

func toAsf(customerLogger *log.Logger, format string, args ...interface{}) {
	customerLogger.Printf(format, args...)
}

// toAsis writes to customerLogger without using sanitizeInput or Scrub
func toAsis(customLogger *log.Logger, args ...interface{}) {
	sanitizedArgs := make([]interface{}, len(args))
	for i, arg := range args {
		if strArg, ok := arg.(string); ok {
			sanitizedArgs[i] = strArg
		} else {
			sanitizedArgs[i] = arg
		}
	}
	customLogger.Println(sanitizedArgs...)
}

// SanitizeTo will Println on your customLogger log.Logger using sanitizeInput and Scrub
func SanitizeTo(customLogger *log.Logger, args ...interface{}) {
	sanitizedArgs := make([]interface{}, len(args))
	for i, arg := range args {
		if strArg, ok := arg.(string); ok {
			sanitizedArgs[i] = sanitizeInput(Scrub(strArg))
		} else {
			sanitizedArgs[i] = arg
		}
	}
	customLogger.Println(sanitizedArgs...)
}

// SanitizefTo will Printf to customLogger log.Logger with sanitizeInput and Scrub
func SanitizefTo(customLogger *log.Logger, format string, args ...interface{}) {
	format = sanitizeInput(Scrub(format))
	sanitizedArgs := make([]interface{}, len(args))
	for i, arg := range args {
		if strArg, ok := arg.(string); ok {
			sanitizedArgs[i] = sanitizeInput(Scrub(strArg))
		} else {
			sanitizedArgs[i] = arg
		}
	}
	customLogger.Printf(format, sanitizedArgs...)
}

// Errorf uses Sprintf and sanitizeInput alongside Scrub on the customLogger log.Logger and returns an errors.New of the line
func Errorf(customLogger *log.Logger, format string, args ...interface{}) error {
	line := fmt.Sprintf(format, args...)
	line = sanitizeInput(Scrub(line))
	customLogger.Println(line)
	return errors.New(line)
}

// SetLogger uses your vLogr for all verbose actions
func SetLogger(newLogger *Logger) error {
	vLogr = newLogger
	if vLogr == nil {
		return errors.New("vLogr not initialized")
	}
	return nil
}

// Options are passed into NewLogger to customize the verbose package
type Options struct {
	Dir      string      // Dir defines the directory to write the log file into
	Name     string      // Name defines the filename prefix of the log file with the extension .log
	Truncate bool        // Truncate sets the FileMode to O_TRUNC or O_APPEND depending on this flag
	DirMode  os.FileMode // DirMode sets the os.FileMode on the logs directory
	FileMode os.FileMode // FileMode sets the os.FileMode on the log file itself
}

// NewLogger creates a log.Logger that prepends [VERBOSE] to the lines logged into Dir/verbose.log
func NewLogger(opts Options) error {
	if len(Dir) == 0 {
		Dir = filepath.Join(".", "logs")
	}
	if len(opts.Dir) > 0 {
		Dir = strings.Clone(opts.Dir)
	}
	dirInfo, infoErr := os.Stat(Dir)
	if infoErr == nil && !dirInfo.IsDir() {
		return Errorf(log.Default(), "%v is not a directory", Dir)
	}
	var dirPerms os.FileMode = 0700
	if opts.DirMode != 0 {
		dirPerms = opts.DirMode
	}
	mkdirErr := os.MkdirAll(Dir, dirPerms)
	if mkdirErr != nil {
		return mkdirErr
	}
	var logFlags int
	if opts.Truncate {
		logFlags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	} else {
		logFlags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}
	var filePerms os.FileMode = 0666
	if opts.FileMode != 0 {
		filePerms = opts.FileMode
	}
	var filename string
	if len(opts.Name) > 0 {
		filename = filepath.Join(Dir, fmt.Sprintf("%s.log", opts.Name))
	} else {
		filename = filepath.Join(Dir, "verbose.log")
	}
	logFile, openErr := os.OpenFile(filename, logFlags, filePerms)
	if openErr != nil {
		return fmt.Errorf("error opening file: %v", openErr)
	}
	vLogr = NewCustomLogger(logFile, "[VERBOSE] ", log.Ldate|log.Ltime|log.Lshortfile, 10)
	if vLogr == nil {
		return errors.New("verbose vLogr is still nil after being defined")
	}
	return nil
}
