# Pixiv 社内 ISUCON 2016, Rust 実装

[Pixiv 社内 ISUCON 2016](https://github.com/catatsuy/private-isu) の Rust 版実装です。

一部他の参考実装通りの機能を満たせていない部分があります。

## セットアップ

```console
$ cd private_isu/webapp
$ git clone https://github.com/hhatto/pixiv-sucon2016-rust rust
$ cd rust
$ curl https://sh.rustup.rs -sSf | sh
```

## ビルド

```console
$ cargo build --release
$ ls target/release/rustwebapp
```
