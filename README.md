# GCS Proxy
A reverse proxy for Google Cloud Storage. This is still a work in progress
because I need to implement some things including but not limited to what listed below.

## To-do
- Add a file listing endpoint
- Add an upload, edit, delete endpoint

## Running
```
cargo run <listener address> <listener port> <bucket name>
```