# Vault Auth Plugin: IMAP Authentication Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows users to authenticate using IMAP.

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, start with this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Usage

### Enable the plugin

```sh
$ vault auth enable -path=imap vault-plugin-auth-imap
Success! Enabled vault-plugin-auth-imap auth method at: imap/
```

### Configure the plugin

You can configure the plugin with the following parameters:

* imap_server
* imap_port ( Default: 993 )
* imap_ssl ( Default: true)

```shell
$ vault write auth/imap/config imap_server=imap.example.com
```

### Create a role for authentication

So you can log in with your email and password, you need to create a role. A role can be limited to be valid only for certain accounts ( = email addresses )

```shell
$ vault write auth/imap/role/privileged-user-only token_policies=admin-policy pricinpals=my-email@example.com,another-mail@example.com
```

On the other hand, you can create a role that is valid for all accounts.

```shell
$ vault write auth/imap/role/readonly token_policies=readonly-policy
```

### Using a role to log in with your email and password

Afterwards, you can use your email and password to log in by using an available role definition:

```shell

```shell
$ vault write auth/imap/login role=readonly username=my-email@example.com password=secret
Key                  Value
---                  -----
token                hvs.CAESICPJO73kqtz......
token_accessor       4s1lxJvhvKl9Oq6CbZuXEcpY
token_duration       768h
token_renewable      true
token_policies       ["default", "readonly-policy"]
identity_policies    []
policies             ["default", "readonly-policy"]
token_meta_role      readonly
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

Next, clone this repository into `vault-plugin-auth-imap`.

To compile a development version of this plugin, run `make build`.
This will put the plugin binary in the `./dist/` folders by using [goreleaser](https://goreleaser.com/).

Run `make` to start a development version of vault with this plugin.

Enable the auth plugin backend using the SSH auth plugin:

```sh
$ vault auth enable -path=imap vault-plugin-auth-imap
Success! Enabled vault-plugin-auth-imap auth method at: imap/
```

### Dev setup

Look into the `./scripts/devsetup.sh` script, this sets up a test environment to a mail server which is related to the environment variable `MAILSERVER`.
