# khf

## TODO

- within a epoch, the same key should always be produced for any given block
    - regardless of updates to that block
- ideally, within an epoch, all of the data except the updated key table and
  number of keys stays the same (within the data structure)
    - we want an L0 node at the end of the root list
    - at commit, fragment the L0 node into appended roots, then add a new L0
