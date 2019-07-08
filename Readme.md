# Authorized Keys Command

The purpose of this cli tools is to retrieve the aws users active public ssh keys from IAM.
It meant to be triggered by sshd on the ec2 instances on every user ssh login.

## Operational prerequisites
* A role arn should be passed in as a form of an EC2 `tag-name` called `auth-account-arn` and the `tag-value` containing the role arn ex.: `arn:aws:iam::434342352745:role/RoleSomeSSH` which has sufficient premission to retrieve the aws users public keys from IAM.
* A machine IAM role which has sufficient permission to assume the above role.

## sshd config example from `/etc/ssh/sshd_config`
```
AuthorizedKeysCommand /usr/local/sbin/authorized_keys_command
```

## Run test
```
go test -v
```

## Build
At build time the application version can be baked into the binary by passing `-X main.version=1.0.0` build parameter.
```
GOOS=linux GOARCH=amd64 go build --ldflags "-X main.version=1.0.0 -extldflags -static -s"
```
## Get app version
```
# /usr/local/sbin/authorized_keys_command/authorized_keys_command --version
Authorized Keys Command Version: '1.0.0'
```



