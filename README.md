# GCS Proxy
A reverse proxy for Google Cloud Storage. This is still a work in progress
because I need to implement some things including but not limited to what listed below.

P.S. Don't hesitate to slap me with PRs as this is my first project in rust
and I haven't finished reading the book either. So you'll most likely find 
silly things here :flushed:

## To-do
- ~~Add a file listing endpoint~~
- Add an upload, edit, delete endpoint
- Make use of the official API (technically done)

## Running
```
cargo run <listener address:port> <bucket name>
```