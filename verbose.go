package verbose

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// VERSION is the current release of the verbose package.
const VERSION = "0.2.0"

// Dir defines the directory into which verbose.log (or the file named by
// Options.Name) is written. It defaults to "./logs" if left empty when
// NewLogger is called. Changing Dir after NewLogger has been called has no
// effect on the open log file.
var Dir string

// vLogr is the package-wide logger. It is nil until NewLogger or SetLogger is
// called successfully. All exported logging functions check for nil via guard()
// before dereferencing it.
var vLogr *Logger

// Common aliases wire the package-level API to the underlying implementation.
// They are vars (not consts) so that tests can swap them out if needed.
//
// Sanitized aliases (secrets are redacted before writing):
//
//	Printf  / Print / Println / Sprint / Sprintf — standard log, secrets redacted
//	Hide    / Hidef                               — explicit sanitize aliases
//	To      / Tof                                 — write to a custom *log.Logger
//
// Unsanitized aliases (bypass all redaction — use with caution):
//
//	Plain / Plainf / Raw / Rawf / Expose / Exposef
var (
	To      = SanitizeTo
	Tof     = SanitizefTo
	Hide    = Sanitize
	Hidef   = Sanitizef
	Printf  = Sanitizef
	Print   = Sanitize
	Println = Sanitize
	Sprint  = Sanitize
	Sprintf = Sanitizef
)

// Plain logs args to the verbose logger without applying sanitizeInput or
// Scrub. Use it only when you deliberately need unsanitised output (e.g.
// debugging the sanitizer itself). Never use it to log values that may contain
// secrets.
//
// It is a no-op (printing to stderr) if NewLogger or SetLogger has not been
// called.
//
// Example:
//
//	verbose.Plain("raw value:", rawString)
func Plain(args ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	vLogr.Logger.Println(args...)
}

// Plainf formats args using format and logs the result to the verbose logger
// without applying sanitizeInput or Scrub. See Plain for caveats.
//
// Example:
//
//	verbose.Plainf("raw value: %s", rawString)
func Plainf(format string, args ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	vLogr.Logger.Printf(format, args...)
}

// Raw is an alias for Plain. See Plain for full documentation.
func Raw(args ...interface{}) {
	Plain(args...)
}

// Rawf is an alias for Plainf. See Plainf for full documentation.
func Rawf(format string, args ...interface{}) {
	Plainf(format, args...)
}

// Expose is an alias for Plain. See Plain for full documentation.
func Expose(args ...interface{}) {
	Plain(args...)
}

// Exposef is an alias for Plainf. See Plainf for full documentation.
func Exposef(format string, args ...interface{}) {
	Plainf(format, args...)
}

// Trace logs v to the verbose logger with a full stack trace appended.
// It is a no-op (printing to stderr) if NewLogger or SetLogger has not been
// called.
//
// Example:
//
//	verbose.Trace("entering handler")
func Trace(v ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	vLogr.Trace(v...)
}

// Tracef formats v using format, logs the result to the verbose logger, and
// appends a full stack trace. It is a no-op (printing to stderr) if NewLogger
// or SetLogger has not been called.
//
// Example:
//
//	verbose.Tracef("handler=%s status=%d", name, code)
func Tracef(format string, v ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	vLogr.Tracef(format, v...)
}

// TraceReturn logs v with a full stack trace and returns the message as an
// error. If NewLogger or SetLogger has not been called the guard error is
// returned directly so the caller is always informed of the failure.
//
// Example:
//
//	return verbose.TraceReturn("unexpected nil pointer")
func TraceReturn(v ...interface{}) error {
	if err := guard(); err != nil {
		return err
	}
	return vLogr.TraceReturn(v...)
}

// TracefReturn formats v using format, logs the result with a full stack trace,
// and returns the formatted message as an error. If NewLogger or SetLogger has
// not been called the guard error is returned directly.
//
// Example:
//
//	return verbose.TracefReturn("invalid config: %v", err)
func TracefReturn(format string, v ...interface{}) error {
	if err := guard(); err != nil {
		return err
	}
	return vLogr.TracefReturn(format, v...)
}

// Return logs v and returns the formatted message as an error. If NewLogger or
// SetLogger has not been called the guard error is returned directly so callers
// always receive a non-nil error in that case.
//
// Example:
//
//	if val == nil {
//	    return verbose.Return("val must not be nil")
//	}
func Return(v ...interface{}) error {
	if err := guard(); err != nil {
		return err
	}
	vLogr.Println(v...)
	return fmt.Errorf("%v", v...)
}

// Returnf formats v using format, logs the result, and returns it as an error.
// If NewLogger or SetLogger has not been called the guard error is returned
// directly.
//
// Example:
//
//	return verbose.Returnf("expected %d got %d", want, got)
func Returnf(format string, v ...interface{}) error {
	if err := guard(); err != nil {
		return err
	}
	vLogr.Printf(format, v...)
	return fmt.Errorf(format, v...)
}

// AsLn writes args to the verbose logger using Println semantics. It is a
// no-op (printing to stderr) if NewLogger or SetLogger has not been called.
func AsLn(args ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	vLogr.Println(args...)
}

func toAsLn(customerLogger *log.Logger, args ...interface{}) {
	customerLogger.Println(args...)
}

func toAsf(customerLogger *log.Logger, format string, args ...interface{}) {
	customerLogger.Printf(format, args...)
}

// SanitizeTo sanitizes each string argument against the registered secrets and
// KeyType patterns, then writes the result to customLogger using Println.
//
// customLogger must be non-nil; passing nil will print an error to stderr and
// return without panicking.
//
// Note: the design philosophy of this package is that all output passing
// through a verbose function is also written to the verbose logger. If you
// need output written only to customLogger without initialising the package
// logger, use customLogger.Println directly.
//
// Example:
//
//	verbose.SanitizeTo(myLogger, "user connected", username)
func SanitizeTo(customLogger *log.Logger, args ...interface{}) {
	if customLogger == nil {
		_, _ = fmt.Fprintf(os.Stderr, "verbose: SanitizeTo called with nil customLogger\n")
		return
	}
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
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

// SanitizefTo sanitizes format and each string argument against the registered
// secrets and KeyType patterns, then writes the formatted result to
// customLogger using Printf.
//
// customLogger must be non-nil; passing nil will print an error to stderr and
// return without panicking.
//
// Example:
//
//	verbose.SanitizefTo(myLogger, "request from %s took %dms", ip, ms)
func SanitizefTo(customLogger *log.Logger, format string, args ...interface{}) {
	if customLogger == nil {
		_, _ = fmt.Fprintf(os.Stderr, "verbose: SanitizefTo called with nil customLogger\n")
		return
	}
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
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

// Errorf formats args using format, sanitizes the result, writes it to
// customLogger, and returns the sanitized string as an error.
//
// customLogger must be non-nil; passing nil will print an error to stderr and
// return that error without panicking.
//
// Unlike other verbose functions, Errorf does not require the package-wide
// logger to be initialised via NewLogger or SetLogger. This allows it to be
// used during early initialisation (e.g. inside NewLogger itself) when vLogr
// is not yet available.
//
// Example:
//
//	if err := db.Ping(); err != nil {
//	    return verbose.Errorf(myLogger, "db ping failed: %v", err)
//	}
func Errorf(customLogger *log.Logger, format string, args ...interface{}) error {
	if customLogger == nil {
		err := errors.New("verbose: Errorf called with nil customLogger")
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}
	line := fmt.Sprintf(format, args...)
	line = sanitizeInput(Scrub(line))
	customLogger.Println(line)
	return errors.New(line)
}

// SetLogger replaces the package-wide verbose logger with newLogger.
// Both newLogger and its inner log.Logger field must be non-nil.
//
// SetLogger is useful when you need to construct the Logger yourself (e.g. to
// write to a custom io.Writer) rather than relying on NewLogger's file-based
// setup.
//
// Example:
//
//	l := verbose.NewCustomLogger(os.Stdout, "[APP] ", log.LstdFlags, 10)
//	if err := verbose.SetLogger(l); err != nil {
//	    panic(err)
//	}
func SetLogger(newLogger *Logger) error {
	if newLogger == nil {
		return errors.New("verbose: SetLogger requires a non-nil *Logger")
	}
	if newLogger.Logger == nil {
		return errors.New("verbose: SetLogger requires a Logger with an initialized inner log.Logger")
	}
	vLogr = newLogger
	return nil
}

// guard returns an error if the package-wide logger has not been initialised.
// All exported functions that write to vLogr call guard() first. This prevents
// nil-pointer panics when the caller has not called NewLogger or SetLogger.
func guard() error {
	if vLogr == nil {
		return errors.New("verbose: NewLogger or SetLogger has not been called")
	}
	return nil
}

// Options configures the verbose logger created by NewLogger.
type Options struct {
	// Dir overrides the package-level Dir variable for this logger instance.
	Dir string

	// Name sets the filename prefix of the log file. The file will be named
	// "<Name>.log". If empty, the file is named "verbose.log".
	Name string

	// Truncate controls whether the log file is truncated (O_TRUNC) or
	// appended to (O_APPEND) on each NewLogger call. Default is append.
	Truncate bool

	// DirMode sets the permission bits used when creating the log directory.
	// Defaults to 0700 if zero.
	DirMode os.FileMode

	// FileMode sets the permission bits used when creating or opening the log
	// file. Defaults to 0666 if zero.
	FileMode os.FileMode
}

// NewLogger initialises the package-wide verbose logger by creating (or
// opening) a log file under Dir (or opts.Dir if provided). After a successful
// call, all sanitising log functions (Printf, Println, Sanitize, etc.) are
// ready to use.
//
// NewLogger is not safe for concurrent use and should be called once at
// program startup, before any goroutines that call the logging functions are
// started.
//
// Example:
//
//	err := verbose.NewLogger(verbose.Options{
//	    Truncate: true,
//	    Dir:      "/var/log/myapp",
//	    Name:     "myapp",
//	    FileMode: 0644,
//	    DirMode:  0755,
//	})
//	if err != nil {
//	    panic(err)
//	}
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

// Sanitize formats args with fmt.Sprint, sanitizes the result against all
// registered secrets, and writes the sanitized string to the verbose logger.
//
// It is a no-op (printing to stderr) if NewLogger or SetLogger has not been
// called.
//
// Note: Sanitize does not return a string. The design philosophy of this
// package is that every string passing through a verbose function is written
// to the verbose logger. Use fmt.Sprintf if you need a formatted string
// without logging it.
func Sanitize(a ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	in := fmt.Sprint(a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}

// Sanitizef formats args using format and fmt.Sprintf, sanitizes both the
// format string and the formatted result against all registered secrets, and
// writes the sanitized output to the verbose logger.
//
// It is a no-op (printing to stderr) if NewLogger or SetLogger has not been
// called.
//
// Note: Sanitizef does not return a string. See Sanitize for the rationale.
func Sanitizef(format string, a ...interface{}) {
	if err := guard(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	format = strings.Clone(sanitizeInput(format))
	in := fmt.Sprintf(format, a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}
