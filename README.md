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

```log
goos: linux
goarch: amd64
pkg: verbose
cpu: Intel(R) Xeon(R) W-3245 CPU @ 3.20GHz
BenchmarkSanitize
BenchmarkSanitize/Sanitize/10Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/5SecretBytes-16        	     200	   5983585 ns/op
BenchmarkSanitize/Sanitize/10Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/10SecretBytes-16       	     188	   5891229 ns/op
BenchmarkSanitize/Sanitize/10Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/20SecretBytes-16       	     189	   5909570 ns/op
BenchmarkSanitize/Sanitize/10Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/40SecretBytes-16       	     181	   6255537 ns/op
BenchmarkSanitize/Sanitize/10Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/80SecretBytes-16       	     172	   6315910 ns/op
BenchmarkSanitize/Sanitize/10Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/160SecretBytes-16      	     193	   6376578 ns/op
BenchmarkSanitize/Sanitize/10Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/10Bytes/420SecretBytes-16      	     182	   6357354 ns/op
BenchmarkSanitize/Sanitize/20Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/5SecretBytes-16        	     196	   6489665 ns/op
BenchmarkSanitize/Sanitize/20Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/10SecretBytes-16       	     166	   6436515 ns/op
BenchmarkSanitize/Sanitize/20Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/20SecretBytes-16       	     170	   6492539 ns/op
BenchmarkSanitize/Sanitize/20Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/40SecretBytes-16       	     177	   7103230 ns/op
BenchmarkSanitize/Sanitize/20Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/80SecretBytes-16       	     177	   6533444 ns/op
BenchmarkSanitize/Sanitize/20Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/160SecretBytes-16      	     181	   6488522 ns/op
BenchmarkSanitize/Sanitize/20Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/20Bytes/420SecretBytes-16      	     164	   6904848 ns/op
BenchmarkSanitize/Sanitize/40Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/5SecretBytes-16        	     168	   6659703 ns/op
BenchmarkSanitize/Sanitize/40Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/10SecretBytes-16       	     164	   6600390 ns/op
BenchmarkSanitize/Sanitize/40Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/20SecretBytes-16       	     166	   7134615 ns/op
BenchmarkSanitize/Sanitize/40Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/40SecretBytes-16       	     165	   7493141 ns/op
BenchmarkSanitize/Sanitize/40Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/80SecretBytes-16       	     180	   7188611 ns/op
BenchmarkSanitize/Sanitize/40Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/160SecretBytes-16      	     158	   6692220 ns/op
BenchmarkSanitize/Sanitize/40Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/40Bytes/420SecretBytes-16      	     177	   7036816 ns/op
BenchmarkSanitize/Sanitize/80Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/5SecretBytes-16        	     168	   7266865 ns/op
BenchmarkSanitize/Sanitize/80Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/10SecretBytes-16       	     165	   7143035 ns/op
BenchmarkSanitize/Sanitize/80Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/20SecretBytes-16       	     164	   7073254 ns/op
BenchmarkSanitize/Sanitize/80Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/40SecretBytes-16       	     147	   7506544 ns/op
BenchmarkSanitize/Sanitize/80Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/80SecretBytes-16       	     157	   7263714 ns/op
BenchmarkSanitize/Sanitize/80Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/160SecretBytes-16      	     153	   7811547 ns/op
BenchmarkSanitize/Sanitize/80Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/80Bytes/420SecretBytes-16      	     158	   6878417 ns/op
BenchmarkSanitize/Sanitize/160Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/5SecretBytes-16       	     144	   8220463 ns/op
BenchmarkSanitize/Sanitize/160Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/10SecretBytes-16      	     139	   8668499 ns/op
BenchmarkSanitize/Sanitize/160Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/20SecretBytes-16      	     140	   8705141 ns/op
BenchmarkSanitize/Sanitize/160Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/40SecretBytes-16      	     141	   8620166 ns/op
BenchmarkSanitize/Sanitize/160Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/80SecretBytes-16      	     122	   9733433 ns/op
BenchmarkSanitize/Sanitize/160Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/160SecretBytes-16     	     145	   8503967 ns/op
BenchmarkSanitize/Sanitize/160Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/160Bytes/420SecretBytes-16     	     152	   8631496 ns/op
BenchmarkSanitize/Sanitize/320Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/5SecretBytes-16       	     128	   9843287 ns/op
BenchmarkSanitize/Sanitize/320Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/10SecretBytes-16      	     100	  10281645 ns/op
BenchmarkSanitize/Sanitize/320Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/20SecretBytes-16      	     100	  10000987 ns/op
BenchmarkSanitize/Sanitize/320Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/40SecretBytes-16      	     123	  10544185 ns/op
BenchmarkSanitize/Sanitize/320Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/80SecretBytes-16      	     100	  12627151 ns/op
BenchmarkSanitize/Sanitize/320Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/160SecretBytes-16     	      99	  11536070 ns/op
BenchmarkSanitize/Sanitize/320Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/320Bytes/420SecretBytes-16     	     100	  11969785 ns/op
BenchmarkSanitize/Sanitize/640Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/5SecretBytes-16       	      69	  15737366 ns/op
BenchmarkSanitize/Sanitize/640Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/10SecretBytes-16      	     100	  15329877 ns/op
BenchmarkSanitize/Sanitize/640Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/20SecretBytes-16      	      76	  13334363 ns/op
BenchmarkSanitize/Sanitize/640Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/40SecretBytes-16      	      86	  14593199 ns/op
BenchmarkSanitize/Sanitize/640Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/80SecretBytes-16      	      75	  13698707 ns/op
BenchmarkSanitize/Sanitize/640Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/160SecretBytes-16     	     100	  18325914 ns/op
BenchmarkSanitize/Sanitize/640Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/640Bytes/420SecretBytes-16     	     100	  16281013 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/5SecretBytes-16      	      40	  28169374 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/10SecretBytes-16     	      38	  27814199 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/20SecretBytes-16     	      45	  25120386 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/40SecretBytes-16     	      42	  24566404 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/80SecretBytes-16     	      49	  24084428 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/160SecretBytes-16    	      43	  24759601 ns/op
BenchmarkSanitize/Sanitize/1280Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/1280Bytes/420SecretBytes-16    	      45	  23341085 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/5SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/5SecretBytes-16      	      25	  44124259 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/10SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/10SecretBytes-16     	      28	  40486917 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/20SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/20SecretBytes-16     	      31	  41148380 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/40SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/40SecretBytes-16     	      27	  42535795 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/80SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/80SecretBytes-16     	      24	  43370117 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/160SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/160SecretBytes-16    	      28	  41067090 ns/op
BenchmarkSanitize/Sanitize/2560Bytes/420SecretBytes
BenchmarkSanitize/Sanitize/2560Bytes/420SecretBytes-16    	      31	  42043945 ns/op
PASS
```

## License

This is released under the Apache 2.0 License.
