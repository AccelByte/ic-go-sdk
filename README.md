# ic-go-sdk

> [!WARNING]
> **Deprecated — no longer maintained.** This module is frozen: no new features,
> bug fixes or security patches will be released. Existing versions remain
> available to read and `go get`, but do not start new work on this module.


This is AccelByte's IC Go SDK for integrating with IC in Go projects.

## Usage

### Importing package

```go
import "github.com/AccelByte/ic-go-sdk"
```

### Creating default IC client

```go
cfg := &iam.Config{
    BaseURL: "<IAM URL>",
    ClientID: "<client ID>",
    ClientSecret: "<client secret>",
}

client := iam.NewDefaultClient(cfg)

cfg := &ic.Config{
    BaseURL:      "<IAM URL>",
    ClientID:     "<client ID>",
    ClientSecret: "<client secret>",
}
client := ic.NewDefaultClient(cfg)
```

### Validate config

```go
_, err := client.ClientToken()
if err != nil {
	logrus.Fatalf("ic-go-sdk start err: %v \n", err)
}
```

### Example:
1. replace the placeholder in ```example/example.go```
2. ```go build example.go```