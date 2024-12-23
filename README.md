# Verbose Package

A utility written in Go that provides a way to scrub 
secrets from a log file that includes additional functions
such as `Trace` and `Return` as well as `To` that allows 
you to write to additional *log.Logger types, while 
leveraging the `Sanitize` and `Scrub` functionality.

## Installation

```bash
go get -u github.com/andreimerlescu/verbose
```

## Usage

```go
package main

import "github.com/andreimerlescu/verbose"

func main(){
    err := verbose.NewLogger(verbose.Options{
        Truncate: true,
        Dir: "/var/logs/go",
        Name: "verbose",
        FileMode: 0644,
        DirMode: 0755,
    })
    if err != nil {
        panic(err)
    }
    
    name := flag.String("name", "", "Name")
    secret := flag.String("secret", "", "Secret")
    flag.Parse()
    
    err = verbose.AddSecret(*secret, "******")
    if err != nil {
        panic("failed to add secret to verbose logger")
    }
    
    if len(*name) == 0 {
        panic(verbose.TracefReturn("Invalid -name provided: %v", *name))
    }
    
    verbose.Plainf("The plain -secret = %s", *secret)
}
```

## Performance

For a `Secrets` structure with 100 hashes inside it and the average length of the line being
written to the log file, the performance of this package can be measured with the benchmark.

See [test_results.txt](test_results.txt) for the complete test results, or you can run: 

```bash
cd ~/work
git clone git@github.com:andreimerlescu/verbose.git
cd verbose
go test .../.
```

## License

This is released under the Apache 2.0 License.
