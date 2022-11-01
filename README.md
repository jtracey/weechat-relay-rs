# A Rust implementation of the WeeChat Relay protocol

weechat-relay-rs is a pure-Rust library for interfacing with a [WeeChat Relay](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html), including sending commands and receiving messages.
This repo also hosts weechat-relay-cli, a minimal terminal application for testing, debugging, and scripting with weechat-relay-rs.
All code is safe Rust, and the library only depends on the standard library and [nom](https://github.com/Geal/nom).

## What is the WeeChat Relay protocol?

[WeeChat](https://weechat.org/), the extensible chat client, can operate as a "relay" for other clients to connect to as ["remote interfaces"](https://weechat.org/about/interfaces/).
This allows users to pick their own interface for their desktop, browser, mobile device, etc..
To use this functionality, the client must use WeeChat's custom [Relay protocol](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html).

## Why does the WeeChat Relay protocol need a library?

Because the protocol is entirely bespoke, and does not use any sort of generalized representation (e.g., XML, JSON, protobufs, etc.), clients cannot rely on popular, well-established libraries for parsing or representing WeeChat relay commands and messages.
The protocol was not written to be cleanly abstracted, and in a lot of ways simply exposes the relay's underlying C representations.
This means that even simple interactions can be cumbersome to get working, with subtle edge cases cropping up in unexpected ways.
A library that is (hopefully) correct should make it a lot easier to get up and running.

## Why a Rust library?

The protocol makes heavy use of complicated structures with many types and various constraints.
Aside from the obvious advantages of memory safety, the compile-time type checks make Rust a language well-suited to consuming the relay protocol, preventing bugs that might otherwise occur in rare edge-cases at run-time.

## What is the status of the library?

The library is "complete" in the sense that it should be able to handle all commands and messages currently possible in the latest WeeChat (other than compressed messages), but is very much incomplete in that **the API is not yet stable**.
It is currently published as something good enough to get fully working code, but there are still rough edges that were left in to get it working quickly.
Feel free to use it, but if you do so, understand that future updates *will* likely break your code.

## How does the CLI tool work?

The CLI tool is not meant to be used as a full WeeChat client, but instead, to play around with the library and WeeChat.
You can also use it to do some basic shell scripting that interfaces with a WeeChat relay.
It takes as input, either in a prompt or from a supplied file or pipe, [WeeChat relay commands](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#commands) in essentially their raw form (parsed locally for basic correctness before sending), and prints any response messages in a mostly-human-readable layout, with the message ID followed by one message object per line.

The the CLI doesn't support compression, but otherwise, it can do most things a WeeChat client can.
Aside from the normal WeeChat relay commands, there are a few commands to interact with the application rather than the relay, currently signified by starting with an underscore (`_`):
 * `_get [n]`: Get n messages from the relay. Most commands expect 0 or 1 messages in response, and the CLI will wait as appropriate for that many messages, but if you want to use the [`sync`](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_sync) command, messages will start coming in asynchronously, so you'll have to use `_get` to see them all. You'll probably want to set the `--timeout` option if you want to use this, else you'll be waiting a while to do anything if there were fewer messages available than you requested.
 * `_sleep [n]`: Sleep n seconds before sending the next command. Can be useful when running commands from a file.
 * `_quit`: Quit the client. If running commands from a file, the application will also quit normally once it gets to the end of the file.

Run the executable with `-h` to see all the invocation options.

An example session:
`cargo run --features cli -- --host "127.0.0.1:9001" --init "my weechat password"`
```
> (before) info version
(before)
inf: ("version": "3.6")
> input core.weechat /upgrade
> (after) info version
(after)
inf: ("version": "3.7.1")
> _quit
```

With the `--script` option or a pipe, you can use hooks from your package manager to automatically upgrade WeeChat when the package upgrades, set up a `cron` job to automatically update channel topics, or anything else you can think of with a shell, all run from your WeeChat instance (no need for separate bot accounts to manage).

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
