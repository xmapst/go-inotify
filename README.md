# GoInotify

Simple Golang inotify wrapper.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/xmapst/go-inotify"
)

func main() {
	w, err := inotify.New()
	if err != nil {
		log.Fatalln(err)
	}

	defer w.Close()

	if err = w.Add(os.TempDir()); err != nil {
		log.Fatalln(err)
	}
	
	for {
		select {
		case event := <- w.Events():
			fmt.Println(event)
		case err = <- w.Errors():
			log.Println(err)
        }
    }
}
```