# Architecture

The V1 data path is:

```text
MCP client -> local policy/approval -> restricted SSH -> forced-command dispatcher -> structured result -> local audit log
```

Each trust boundary validates strict typed input and fails closed.
